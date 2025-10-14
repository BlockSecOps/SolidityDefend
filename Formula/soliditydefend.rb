# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/SolidityOps/SolidityDefend"
  version "1.0.0"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.0/soliditydefend-v1.0.0-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_ARM64"
    else
      url "https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.0/soliditydefend-v1.0.0-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_X86"
    end
  end

  on_linux do
    url "https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.0/soliditydefend-v1.0.0-x86_64-unknown-linux-gnu.tar.gz"
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
    # Test that the binary runs and shows version
    assert_match "soliditydefend 1.0.0", shell_output("#{bin}/soliditydefend --version")

    # Test help command
    assert_match "USAGE:", shell_output("#{bin}/soliditydefend --help")

    # Test list-detectors command
    assert_match "detectors", shell_output("#{bin}/soliditydefend --list-detectors")
  end
end
