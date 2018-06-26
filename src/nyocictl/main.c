
#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <libgen.h>
#include <time.h>
#include <poll.h>

#if !HAVE_FGETLN
#include <missing/fgetln.h>
#endif

#if HAVE_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#ifndef HAS_LIBEDIT_COMPLETION_ENTRY_BUG
#define HAS_LIBEDIT_COMPLETION_ENTRY_BUG  defined(__APPLE__)
#endif
#endif

#include <libnyoci/libnyoci.h>

#if NYOCI_PLAT_TLS_OPENSSL
#include <openssl/ssl.h>
#endif

#include "string-utils.h"
#include "nyoci-missing.h"

#include "cmd_list.h"
#include "cmd_get.h"
#include "cmd_post.h"
#include "cmd_repeat.h"
#include "cmd_delete.h"

#include "nyocictl.h"

#include <libnyoci/url-helpers.h>

bool show_headers = 0;
static int gRet = 0;
static nyoci_t gLibNyociInstance;
static bool istty = true;

char*get_next_arg(char *buf, char **rest);

static arg_list_item_t option_list[] = {
	{ 'h', "help",	NULL, "Print Help"				},
	{ 'v', "version", NULL, "Print Version Information" },
	{ 'd', "debug", NULL, "Enable debugging mode"	},
	{ 'p', "port",	"port", "Port number"				},
	{ 'f', NULL,	"filename", "Read commands from file" },
#if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	{ 0, NULL,	"ssl-*", "SSL Configuration commands (see docs)" },
#endif
#if NYOCI_DTLS
	{ 'i', "identity",	"identity", "Set DTLS PSK identity" },
	{ 'P', "psk",	"string", "Set DTLS PSK as a string" },
#endif
	{ 0 }
};

void print_commands(void);

static int
tool_cmd_help(
	nyoci_t nyoci, int argc, char* argv[]
) {
	if((2 == argc) && (0 == strcmp(argv[1], "--help"))) {
		printf("Help not yet implemented for this command.\n");
		return ERRORCODE_HELP;
	}

	if((argc == 2) && argv[1][0] != '-') {
		const char *argv2[2] = {
			argv[1],
			"--help"
		};
		return exec_command(nyoci, 2, (char**)argv2);
	} else {
		print_commands();
	}
	return ERRORCODE_HELP;
}


static int
tool_cmd_cd(
	nyoci_t nyoci, int argc, char* argv[]
) {
	int ret = 0;

	if((2 == argc) && (0 == strcmp(argv[1], "--help"))) {
		fprintf(stderr,"%s: Help not yet implemented for this command.\n",argv[0]);
		ret = ERRORCODE_HELP;
	}

	if(argc == 1) {
		printf("%s\n", getenv("NYOCI_CURRENT_PATH"));
		ret = ERRORCODE_HELP;
	} else if(argc == 2) {
		char url[2000];
		strncpy(url, getenv("NYOCI_CURRENT_PATH"),sizeof(url)-1);
		if(!url_change(url, argv[1])) {
			fprintf(stderr,"%s: Bad URL.\n",argv[0]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}
		if(url[0] && '/'!=url[strlen(url)-1] && !strchr(url,'?')) {
			strcat(url,"/");
		}

		char* url_check = strdup(url);
		struct url_components_s components = {0};

		url_parse(url_check,&components);
		free(url_check);
		if(!components.host) {
			fprintf(stderr,"%s: Bad URL.\n",argv[0]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		setenv("NYOCI_CURRENT_PATH", url, 1);
	}

bail:
	return ret;
}


struct {
	const char* name;
	const char* desc;
	int			(*entrypoint)(
		nyoci_t nyoci, int argc, char* argv[]);
	int			isHidden;
} commandList[] = {
	{
		"get",
		"Fetches the value of a resource.",
		&tool_cmd_get
	},
	{ "cat", NULL, &tool_cmd_get, 1 },
	{
		"post",
		"Triggers an event.",
		&tool_cmd_post
	},
	{
		"put",
		"Overwrites a resource.",
		&tool_cmd_post
	},
	{
		"delete",
		"Deletes a resource.",
		&tool_cmd_delete
	},
	{ "rm",	 NULL, &tool_cmd_delete, 1 },
	{ "del",	 NULL, &tool_cmd_delete, 1 },
	{
		"list",
		"Displays the contents of a folder.",
		&tool_cmd_list
	},
	{ "ls",	 NULL, &tool_cmd_list, 1 },
	{ "dir",	 NULL, &tool_cmd_list, 1 },
	{
		"observe",
		"observes changes in the value of a resource.",
		&tool_cmd_get
	},
	{ "obs", NULL, &tool_cmd_get, 1 },
	{
		"repeat",
		"Repeat the specified command",
		&tool_cmd_repeat
	},
	{ "cd",	 "Change current directory or URL (command mode)", &tool_cmd_cd },
	{ "quit", "Terminate command line mode.", NULL },

	{ "help", "Display this help.", &tool_cmd_help },
	{ "?",	 NULL, &tool_cmd_help,  1 },


	{ NULL }
};

void
print_commands() {
	int i;

	printf("Commands:\n");
	for(i = 0; commandList[i].name; ++i) {
		if(commandList[i].isHidden)
			continue;
		printf(
			"   %s %s%s\n",
			commandList[i].name,
			&"                     " [ strlen(commandList[i].name)],
			commandList[i].desc
		);
	}
}

int
exec_command(
	nyoci_t nyoci, int argc, char * argv[]
) {
	int ret = 0;
	int j;

	require(argc, bail);

	if((strcmp(argv[0],
				"quit") == 0) ||
			(strcmp(argv[0],
				"exit") == 0) || (strcmp(argv[0], "q") == 0)) {
		ret = ERRORCODE_QUIT;
		goto bail;
	}

	for(j = 0; commandList[j].name; ++j) {
		if(strcmp(argv[0], commandList[j].name) == 0) {
			if(commandList[j].entrypoint) {
				ret = commandList[j].entrypoint(nyoci, argc, argv);
				goto bail;
			} else {
				fprintf(stderr,
					"The command \"%s\" is not yet implemented.\n",
					commandList[j].name);
				ret = ERRORCODE_NOCOMMAND;
				goto bail;
			}
		}
	}

	fprintf(stderr, "The command \"%s\" is not recognised.\n", argv[0]);

	ret = ERRORCODE_BADCOMMAND;

bail:
	return ret;
}

char*
get_next_arg(char *buf, char **rest)
{
	char* ret = NULL;
	char quote_type = 0;
	char* write_iter = NULL;

	// Trim whitespace
	while (isspace(*buf)) {
		buf++;
	};

	// Skip if we are empty or the start of a comment.
	if ((*buf == 0) || (*buf == '#')) {
		goto bail;
	}

	write_iter = ret = buf;

	while (*buf != 0) {
		if (quote_type != 0) {
			// We are in the middle of a quote, so we are
			// looking for matching end of the quote.
			if (*buf == quote_type) {
				quote_type = 0;
				buf++;
				continue;
			}
		} else {
			if (*buf == '"' || *buf == '\'') {
				quote_type = *buf++;
				continue;
			}

			// Stop parsing arguments if we hit unquoted whitespace.
			if (isspace(*buf)) {
				buf++;
				break;
			}
		}

		// Allow for slash-escaping
		if ((buf[0] == '\\') && (buf[1] != 0)) {
			buf++;
		}

		*write_iter++ = *buf++;
	}

	*write_iter = 0;

bail:
	if (rest) {
		*rest = buf;
	}
	return ret;
}

#if HAVE_LIBREADLINE
static bool history_disabled;
#endif

static void process_input_line(char *l) {
	char *inputstring;
	char *argv2[100];
	char **ap = argv2;
	int argc2 = 0;

	if(!l[0]) {
		l = NULL;
		goto bail;
	}
	l = strdup(l);
#if HAVE_LIBREADLINE
	if(!history_disabled)
		add_history(l);
#endif

	inputstring = l;

	while((*ap = get_next_arg(inputstring,&inputstring))) {
		if(**ap != '\0') {
			ap++;
			argc2++;
		}
	}
	if(argc2 > 0) {
		gRet = exec_command(gLibNyociInstance, argc2, argv2);
		if(gRet == ERRORCODE_QUIT)
			goto bail;
		else if(gRet && (gRet != ERRORCODE_HELP))
			fprintf(stderr,"Error %d\n", gRet);

#if HAVE_LIBREADLINE
		if(!history_disabled)
			write_history(getenv("NYOCI_HISTORY_FILE"));
#endif
	}

bail:
	free(l);
	return;
}

#if HAVE_LIBREADLINE
static char* get_current_prompt() {
	static char prompt[MAX_URL_SIZE+40] = {};
	char* current_nyoci_path = getenv("NYOCI_CURRENT_PATH");
	snprintf(prompt,
		sizeof(prompt),
		"%s"
		"> ",
		current_nyoci_path ? current_nyoci_path : ""
	);
	return prompt;
}

static void process_input_readline(char *l) {
	process_input_line(l);
	if(istty) {
#if HAVE_RL_SET_PROMPT
		if(gRet==ERRORCODE_QUIT)
			rl_set_prompt("");
		else
#endif
			rl_callback_handler_install(get_current_prompt(), &process_input_readline);
	}
}
#endif

// MARK: -

#if HAVE_LIBREADLINE

static char *
nyoci_command_generator(
	const char *text,
	int state
) {
	static int list_index;
	static size_t len;
	const char *name;

	/* If this is a new word to complete, initialize now.  This includes
	 saving the length of TEXT for efficiency, and initializing the index
	 variable to 0. */
	if (!state)
	{
		list_index = 0;
		len = strlen (text);
	}

	/* Return the next name which partially matches from the command list. */
	while ((name = commandList[list_index].name))
	{
		list_index++;

		if (strncmp (name, text, len) == 0)
			return (strdup(name));
	}

	/* If no names matched, then return NULL. */
	return ((char *)NULL);
}

static char *
nyoci_directory_generator(
	const char *text,
	int state
) {
	char *ret = NULL;
	static size_t len;
	static FILE* temp_file = NULL;
	const char *name;
	static char* prefix;
	static char* fragment;
	size_t namelen = 0;

	rl_filename_completion_desired = 1;

	// Don't add the internal commands to the history.
	history_disabled = true;

	/* If this is a new word to complete, initialize now.  This includes
	 saving the length of TEXT for efficiency, and initializing the index
	 variable to 0. */
	if (!state)
	{
		size_t i;

		if(temp_file)
			fclose(temp_file);

		temp_file = tmpfile();

		require(temp_file!=NULL,bail);

		free(prefix);
		free(fragment);

		prefix = strdup(text);

		// Figure out where the last path component starts.
		for(i=strlen(prefix);i && prefix[i]!='/';i--);

		if(prefix[i]=='/') {
			prefix[i] = 0;
			if(i==0) {
				prefix = strdup("/");
			}
			fragment = strdup(prefix+i+1);
		} else {
			fragment = strdup(prefix);
			free(prefix);
			prefix = strdup(".");
		}
		char* cmdline = NULL;
		FILE* real_stdout = stdout;

		if(url_is_root(getenv("NYOCI_CURRENT_PATH")) && !url_is_root(prefix)) {
			if(!i) {
				asprintf(&cmdline, "list --filename-only --timeout 750 /.well-known/core");
				require(cmdline,bail);
				//fprintf(stderr,"\n[cmd=\"%s\"] ",cmdline);

				fprintf(temp_file,".well-known/\n");

				stdout = temp_file;
				process_input_line(cmdline);
				stdout = real_stdout;
				free(cmdline);
			} else {
				if(strequal_const(prefix, ".well-known")) {
					fprintf(temp_file,"core\n");
				}
			}
		} else {
			asprintf(&cmdline, "list --filename-only --timeout 1000 \"%s\"",prefix);
			require(cmdline,bail);

			stdout = temp_file;
			if(strequal_const(fragment, "."))
				fprintf(temp_file,"../\n");
			process_input_line(cmdline);
			stdout = real_stdout;
			free(cmdline);
		}

		rewind(temp_file);
		len = strlen(fragment);
	}

	require(temp_file!=NULL,bail);

	while ((name = fgetln(temp_file, &namelen)))
	{
		if(namelen<len)
			continue;
		//fprintf(stderr,"\n[candidate=\"%s\" namelen=%d] ",name,namelen);
		if(url_is_root(getenv("NYOCI_CURRENT_PATH")) && strequal_const(prefix,".")) {
			while(name[0]=='/') {
				name++;
				namelen--;
			}
		}
		if (strncmp (name, fragment, len) == 0) {
			while(namelen && isspace(name[namelen-1])) { namelen--; }
			//namelen--;
			if(name[namelen-1]=='/')
				rl_completion_append_character = 0;

			if(	strequal_const(prefix, "/")
				|| strequal_const(prefix, ".")
				|| name[0]=='/'
				||(url_is_root(getenv("NYOCI_CURRENT_PATH")) && strequal_const(prefix,"."))
			) {
				ret = strndup(name,namelen);
			} else {
				char* tmp = strndup(name,namelen);
				if(prefix[strlen(prefix)-1]=='/')
					asprintf(&ret, "%s%s",prefix,tmp);
				else
					asprintf(&ret, "%s/%s",prefix,tmp);
				free(tmp);
			}
			break;
		}
	}


bail:
	history_disabled = false;
	//fprintf(stderr,"\n[prefix=\"%s\" ret=\"%s\"] ",prefix,ret);

	return ret;
}

static char **
nyoci_attempted_completion (
	const char *text,
	int start,
	int end
) {
	char **matches;

	matches = (char **)NULL;

	/* If this word is at the start of the line, then it is a command
	 to complete.  Otherwise it is the name of a file in the current
	 directory. */
	if(start == 0) {
		matches = rl_completion_matches (text, &nyoci_command_generator);
	} else {
		if(text[0]=='-') {
			// Argument Completion.
			// TODO: Writeme!
			rl_attempted_completion_over = 1;
			//fprintf(stderr,"\nrl_line_buffer=\"%s\"\n",rl_line_buffer);
		}
	}

	return (matches);
}

static int
initialize_readline() {
	int ret = 0;

	require_action(NULL != readline, bail, ret = ERRORCODE_NOREADLINE);
	rl_initialize();

	rl_readline_name = "nyoci";
	rl_completer_word_break_characters = " \t\n\"\\'`@$><|&{("; // Removed '=' ';'
	/* Tell the completer that we want a crack first. */
	rl_attempted_completion_function = nyoci_attempted_completion;
#if HAS_LIBEDIT_COMPLETION_ENTRY_BUG
	// Apple's LIBEDIT has some problems
	rl_completion_entry_function = (void*)nyoci_directory_generator;
#else
	rl_completion_entry_function = nyoci_directory_generator;
#endif

	using_history();
	read_history(getenv("NYOCI_HISTORY_FILE"));
	rl_instream = stdin;

	rl_callback_handler_install(get_current_prompt(), &process_input_readline);

bail:
	return ret;
}
#endif

#ifndef PACKAGE_TARNAME
#define PACKAGE_TARNAME "nyoci"
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "0.0"
#endif

static void
print_version() {
	printf(PACKAGE_TARNAME"ctl "PACKAGE_VERSION"\n");
}

// MARK: -
// MARK: DTLS Stuff

#if NYOCI_DTLS
char gNyocictlClientPskIdentity[128];
uint8_t gNyocictlClientPsk[128];
int gNyocictlClientPskLength = 0;

static unsigned int
nyocictl_plat_tls_client_psk_cb(
	void* context,
	const char *hint,
	char *identity, unsigned int max_identity_len,
	unsigned char *psk, unsigned int max_psk_len
) {
	// We ignore the hint.

	strlcpy(identity, gNyocictlClientPskIdentity, max_identity_len);

	if (max_psk_len > gNyocictlClientPskLength) {
		max_psk_len = gNyocictlClientPskLength;
	}

	memcpy(psk, gNyocictlClientPsk, max_psk_len);

	return max_psk_len;
}

static unsigned int
nyocictl_plat_tls_server_psk_cb(
	void* context,
	const char *identity,
	unsigned char *psk, unsigned int max_psk_len
) {
	return 0;
}
#endif // if NYOCI_DTLS

// MARK: -



int
main(
	int argc, char * argv[], char * envp[]
) {
	int i, debug_mode = 0;
	uint16_t port = 61616;

#if NYOCI_DTLS
	uint16_t ssl_port = 61617;
	int ssl_ret;
	nyoci_plat_tls_context_t ssl_ctx = NYOCI_PLAT_TLS_DEFAULT_CONTEXT;

#if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	SSL_CONF_CTX* ssl_conf_ctx = SSL_CONF_CTX_new();

#if HAVE_OPENSSL_DTLS_METHOD
	ssl_ctx = SSL_CTX_new(DTLS_method());
#else // if HAVE_OPENSSL_DTLS_METHOD
	ssl_ctx = SSL_CTX_new(DTLSv1_2_method());
#endif // else HAVE_OPENSSL_DTLS_METHOD

	// Make sure the PSK mechanisms are present.
	SSL_CTX_set_cipher_list(ssl_ctx, "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2:-CAMILLA:PSK");

	SSL_CONF_CTX_set_ssl_ctx(ssl_conf_ctx, ssl_ctx);
	SSL_CONF_CTX_set_flags(ssl_conf_ctx, SSL_CONF_FLAG_CLIENT|SSL_CONF_FLAG_CERTIFICATE|SSL_CONF_FLAG_SHOW_ERRORS);
	SSL_CONF_CTX_set_flags(ssl_conf_ctx, SSL_CONF_FLAG_FILE);
	SSL_CONF_CTX_set1_prefix(ssl_conf_ctx, "NYOCICTL_SSL_");

#ifdef SSL_CONF_FLAG_REQUIRE_PRIVATE
	SSL_CONF_CTX_set_flags(ssl_conf_ctx, SSL_CONF_FLAG_REQUIRE_PRIVATE);
#endif

	for (i = 0; envp[i]; i++) {
		char key[256] = {};
		char* value = key;
		strlcpy(key, envp[i], sizeof(key));
		strsep(&value, "=");

		ssl_ret = SSL_CONF_cmd(ssl_conf_ctx, key, value);
		switch(ssl_ret) {
		case 1:
		case 2:
#if DEBUG
			fprintf(stderr, "%s: OpenSSL => %s\n", argv[0], envp[i]);
#endif
			break;
		case -2:
			// Skippit.
			break;
		default:
			fprintf(stderr, "%s: error: OpenSSL did not like %s\n", argv[0], envp[i]);
			break;
		}
	}

	SSL_CONF_CTX_clear_flags(ssl_conf_ctx, SSL_CONF_FLAG_FILE);
	SSL_CONF_CTX_set_flags(ssl_conf_ctx, SSL_CONF_FLAG_CMDLINE);
	SSL_CONF_CTX_set1_prefix(ssl_conf_ctx, "--ssl-");

#endif // if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW

#endif // if NYOCI_DTLS

	srandom((unsigned)time(NULL));

	BEGIN_LONG_ARGUMENTS(gRet)
#if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	// Handle OpenSSL configuration options on the command line
	else if ((ssl_ret = SSL_CONF_cmd(ssl_conf_ctx, argv[i], argv[i+1])) != -2) {
		if (ssl_ret == 2) {
			i++;
		} else if (ssl_ret == 0) {
			fprintf(stderr,
				"%s: error: Argument rejected: %s\n",
				argv[0],
				argv[i]);
			return ERRORCODE_BADARG;
		} else if (ssl_ret < 0) {
			fprintf(stderr,
				"%s: error: OpenSSL runtime error for: %s\n",
				argv[0],
				argv[i]);
			return ERRORCODE_BADARG;
		}
	}
#endif // if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	HANDLE_LONG_ARGUMENT("port") port = (uint16_t)strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("debug") debug_mode++;

	HANDLE_LONG_ARGUMENT("version") {
		print_version();
		gRet = 0;
		goto bail;
	}
	HANDLE_LONG_ARGUMENT("help") {
		print_version();
		print_arg_list_help(option_list,
			argv[0],
			"[options] <sub-command> [args]");
		print_commands();
		gRet = ERRORCODE_HELP;
		goto bail;
	}
#if NYOCI_DTLS
	HANDLE_LONG_ARGUMENT("identity") {
		strlcpy(gNyocictlClientPskIdentity, argv[++i], sizeof(gNyocictlClientPskIdentity));
	}
	HANDLE_LONG_ARGUMENT("psk") {
		strlcpy((char*)gNyocictlClientPsk, argv[++i], sizeof(gNyocictlClientPsk));
		gNyocictlClientPskLength = strlen((const char*)gNyocictlClientPsk);
	}
#endif
	BEGIN_SHORT_ARGUMENTS(gRet)
	HANDLE_SHORT_ARGUMENT('p') port = (uint16_t)strtol(argv[++i], NULL, 0);
	HANDLE_SHORT_ARGUMENT('d') debug_mode++;
#if HAVE_LIBREADLINE
	HANDLE_SHORT_ARGUMENT('f') {
		stdin = fopen(argv[++i], "r");
		if (!stdin) {
			fprintf(stderr,
				"%s: error: Unable to open file \"%s\".\n",
				argv[0],
				argv[i - 1]);
			return ERRORCODE_BADARG;
		}
	}
#endif
#if NYOCI_DTLS
	HANDLE_SHORT_ARGUMENT('i') {
		strlcpy(gNyocictlClientPskIdentity, argv[++i], sizeof(gNyocictlClientPskIdentity));
	}
	HANDLE_SHORT_ARGUMENT('P') {
		strlcpy((char*)gNyocictlClientPsk, argv[++i], sizeof(gNyocictlClientPsk));
		gNyocictlClientPskLength = strlen((const char*)gNyocictlClientPsk);
	}
#endif

	HANDLE_SHORT_ARGUMENT('v') {
		print_version();
		gRet = 0;
		goto bail;
	}
	HANDLE_SHORT_ARGUMENT2('h', '?') {
		print_version();
		print_arg_list_help(option_list,
			argv[0],
			"[options] <sub-command> [args]");
		print_commands();
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	HANDLE_OTHER_ARGUMENT() {
		break;
	}
	END_ARGUMENTS

	NYOCI_LIBRARY_VERSION_CHECK();

	show_headers = debug_mode;
	istty = isatty(fileno(stdin));

	gLibNyociInstance = nyoci_create();

	if (!gLibNyociInstance) {
		fprintf(stderr,"%s: FATAL-ERROR: Unable to initialize nyoci instance! \"%s\" (%d)\n",argv[0],strerror(errno),errno);
		return ERRORCODE_INIT_FAILURE;
	}

	if (nyoci_plat_bind_to_port(gLibNyociInstance, NYOCI_SESSION_TYPE_UDP, port) != NYOCI_STATUS_OK) {
		if(nyoci_plat_bind_to_port(gLibNyociInstance, NYOCI_SESSION_TYPE_UDP, 0) != NYOCI_STATUS_OK) {
			fprintf(stderr,"%s: FATAL-ERROR: Unable to bind to port! \"%s\" (%d)\n",argv[0],strerror(errno),errno);
			return ERRORCODE_INIT_FAILURE;
		}
		port = 0;
	}

#if NYOCI_DTLS
#if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
#if HAVE_OPENSSL_SSL_CONF_FINISH
	SSL_CONF_finish(ssl_conf_ctx);
#endif
	SSL_CONF_CTX_free(ssl_conf_ctx);
	ssl_conf_ctx = NULL;
#endif
	if (nyoci_plat_tls_set_context(gLibNyociInstance, (void*)ssl_ctx) == NYOCI_STATUS_OK) {
		if (nyoci_plat_bind_to_port(gLibNyociInstance, NYOCI_SESSION_TYPE_DTLS, ssl_port) != NYOCI_STATUS_OK) {
			if(nyoci_plat_bind_to_port(gLibNyociInstance, NYOCI_SESSION_TYPE_DTLS, 0) != NYOCI_STATUS_OK) {
				fprintf(stderr,"%s: ERROR: Unable to bind to ssl port! \"%s\" (%d)\n",argv[0],strerror(errno),errno);
			}
			ssl_port = 0;
		}
	} else {
		fprintf(stderr,"%s: ERROR: Unable to set ssl context!\n",argv[0]);
	}

	if ( gNyocictlClientPskIdentity[0] != 0
	  || gNyocictlClientPskLength != 0
	) {
		nyoci_plat_tls_set_client_psk_callback(gLibNyociInstance, &nyocictl_plat_tls_client_psk_cb, NULL);
	}
#endif

	setenv("NYOCI_CURRENT_PATH", "coap://localhost/", 0);

	nyoci_set_proxy_url(gLibNyociInstance, getenv("COAP_PROXY_URL"));

	if(i < argc) {
		if(((i + 1) == argc) && (0 == strcmp(argv[i], "help")))
			print_arg_list_help(option_list,
				argv[0],
				"[options] <sub-command> [args]");

		if((0 !=
				strncmp(argv[i], "coaps:",
					6)) && (0 != strncmp(argv[i], "coap:", 5))) {
			gRet = exec_command(gLibNyociInstance, argc - i, argv + i);
#if HAVE_LIBREADLINE
			if(gRet || (0 != strcmp(argv[i], "cd")))
#endif
			goto bail;
		} else {
			setenv("NYOCI_CURRENT_PATH", argv[i], 1);
		}
	}

	if(istty) {
		fprintf(stderr,"coap on port %d.\n",nyoci_plat_get_port(gLibNyociInstance));
#if NYOCI_DTLS
		fprintf(stderr,"coaps on port %d.\n", ssl_port);
#endif
#if !HAVE_LIBREADLINE
		print_arg_list_help(option_list,
			argv[0],
			"[options] <sub-command> [args]");
		print_commands();
		gRet = ERRORCODE_NOCOMMAND;
		goto bail;
#else   // HAVE_LIBREADLINE
		setenv("NYOCI_HISTORY_FILE", tilde_expand("~/.nyoci_history"), 0);

		require_noerr(gRet = initialize_readline(),bail);

#endif  // HAVE_LIBREADLINE
	}

	// Command mode.
	while((gRet != ERRORCODE_QUIT) && !feof(stdin)) {
#if HAVE_LIBREADLINE
		if(istty) {
			struct pollfd polltable[10] = {
				{ fileno(stdin), POLLIN | POLLHUP, 0 },
			};
			int pollfdcount = 1;
			int nyocipollfdcount = 0;
			int nyocimaxpollfds = sizeof(polltable)/sizeof(*polltable)-1;

			nyocipollfdcount = nyoci_plat_update_pollfds(gLibNyociInstance, polltable+1, nyocimaxpollfds);

			if (nyocipollfdcount < 0) {
				perror("nyoci_plat_update_pollfds");
				abort();
			}

			if (nyocipollfdcount > nyocimaxpollfds) {
				perror("too many fds");
				abort();
			}

			pollfdcount += nyocipollfdcount;

			if (poll(
					polltable,
					pollfdcount,
					nyoci_get_timeout(gLibNyociInstance)
				) < 0
			) {
				if(errno == EINTR) {
					// We just caught a signal.
					// Do nothing.
				} else {
					break;
				}
			}

			if(polltable[0].revents)
				rl_callback_read_char();
		} else
#endif  // HAVE_LIBREADLINE
		{
			char linebuffer[200];
			fgets(linebuffer, sizeof(linebuffer), stdin);
			process_input_line(linebuffer);
		}

		nyoci_plat_process(gLibNyociInstance);
	}

bail:

#if HAVE_LIBREADLINE
	rl_callback_handler_remove();
#endif  // HAVE_LIBREADLINE

	if (gRet == ERRORCODE_QUIT) {
		gRet = 0;
	}

	if (gLibNyociInstance) {
		nyoci_release(gLibNyociInstance);
	}
	return gRet;
}
