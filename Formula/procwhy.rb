class Procwhy < Formula
  desc "Diagnostic snapshot tool for interrogating processes and explaining their footprint"
  homepage "https://github.com/CtxtArc/procwhy"
  version "0.1.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/CtxtArc/procwhy/releases/download/v#{version}/procwhy-aarch64-apple-darwin.tar.gz"
      # sha256 "..." # dynamically calculated on release
    else
      url "https://github.com/CtxtArc/procwhy/releases/download/v#{version}/procwhy-x86_64-apple-darwin.tar.gz"
      # sha256 "..." # dynamically calculated on release
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/CtxtArc/procwhy/releases/download/v#{version}/procwhy-aarch64-unknown-linux-gnu.tar.gz"
      # sha256 "..." # dynamically calculated on release
    else
      url "https://github.com/CtxtArc/procwhy/releases/download/v#{version}/procwhy-x86_64-unknown-linux-gnu.tar.gz"
      # sha256 "..." # dynamically calculated on release
    end
  end

  def install
    bin.install "procwhy"
  end

  test do
    assert_match "Why is my process doing this?", shell_output("#{bin}/procwhy --help")
  end
end
