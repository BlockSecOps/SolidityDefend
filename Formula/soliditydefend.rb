# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "1.10.11"
  license "MIT OR Apache-2.0"

  on_macos do
    url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.11/soliditydefend-v1.10.11-x86_64-apple-darwin.tar.gz"
    sha256 "768afb89b2e3bd918f76637dede153255b5c5e562daa52e88b2b0ded2777a691"
  end

  on_linux do
    url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.11/soliditydefend-v1.10.11-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "ca6009dde8efea899f5e50653a99ccc4fa552541ac0b5acf1bc61d91af685dd3"
  end

  def install
    bin.install "soliditydefend"

    # Install shell completions
    if File.exist?("completions/soliditydefend.bash")
      bash_completion.install "completions/soliditydefend.bash"
    end
    if File.exist?("completions/soliditydefend.zsh")
      zsh_completion.install "completions/soliditydefend.zsh"
    end
    if File.exist?("completions/soliditydefend.fish")
      fish_completion.install "completions/soliditydefend.fish"
    end

    # Install man page if available
    if File.exist?("man/soliditydefend.1")
      man1.install "man/soliditydefend.1"
    end
  end

  test do
    # Test that the binary runs and shows version (outputs to stderr with exit 1)
    assert_match "soliditydefend 1.10.11", shell_output("#{bin}/soliditydefend --version 2>&1", 1)

    # Test help command (outputs to stderr with exit 1)
    assert_match "Usage:", shell_output("#{bin}/soliditydefend --help 2>&1", 1)

    # Test list-detectors command (exit 0)
    output = shell_output("#{bin}/soliditydefend --list-detectors 2>&1")
    assert_match "detector", output.downcase
  end
end
