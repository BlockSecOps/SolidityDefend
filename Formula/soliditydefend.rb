# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "1.10.11"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.11/soliditydefend-v1.10.11-darwin-arm64.tar.gz"
      sha256 "8a6929d0283f09c141ae443e6e6838cba39dbebd6cb4b4edeeeeec98fce2d509"
    else
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.11/soliditydefend-v1.10.11-darwin-x86_64.tar.gz"
      sha256 "8a6929d0283f09c141ae443e6e6838cba39dbebd6cb4b4edeeeeec98fce2d509"
    end
  end

  on_linux do
    url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.11/soliditydefend-v1.10.11-linux-x86_64.tar.gz"
    sha256 "REPLACE_WITH_ACTUAL_SHA256_LINUX"
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
