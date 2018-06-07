require 'formula'

class Libnyoci < Formula
  homepage 'https://github.com/darconeous/libnyoci'
  url 'https://github.com/darconeous/libnyoci.git', :tag => 'full/0.07.00rc1'
  head 'https://github.com/darconeous/libnyoci.git', :using => :git, :branch => 'master'
  sha256 ''
  version '0.07.00rc1'

#  depends_on 'readline' => :recommended
#  depends_on 'curl' => :recommended
   depends_on 'openssl@1.1' => :recommended

  if build.head?
    depends_on 'autoconf' => :build
    depends_on 'automake' => :build
    depends_on 'libtool' => :build
  end

  def install

  system "[ -x configure ] || PATH=\"#{HOMEBREW_PREFIX}/bin:$PATH\" ./bootstrap.sh" if build.head?
    system "./configure",
      "--disable-debug",
      "--disable-dependency-tracking",
      "--enable-tls",
      "--prefix=#{prefix}"
    system "make install"
  end

  def test
    system "nyocictl -p 10342 cat -i coap://localhost:10342/"
  end
end
