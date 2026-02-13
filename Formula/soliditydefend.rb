# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "1.10.23"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-macos-aarch64.tar.gz"
      sha256 "MACOS_ARM64_SHA256_PLACEHOLDER"
    end
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-macos-x86_64.tar.gz"
      sha256 "MACOS_X86_64_SHA256_PLACEHOLDER"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-linux-x86_64.tar.gz"
      sha256 "LINUX_X86_64_SHA256_PLACEHOLDER"
    end
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-linux-aarch64.tar.gz"
      sha256 "LINUX_AARCH64_SHA256_PLACEHOLDER"
    end
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
      fish_completion.install "completions/solidifydefend.fish"
    end

    # Install man page if available
    if File.exist?("man/soliditydefend.1")
      man1.install "man/soliditydefend.1"
    end
  end

  test do
    assert_match "soliditydefend 1.10.23", shell_output("#{bin}/soliditydefend --version 2>&1", 1)
    assert_match "Usage:", shell_output("#{bin}/soliditydefend --help 2>&1", 1)
    output = shell_output("#{bin}/soliditydefend --list-detectors 2>&1")
    assert_match "detector", output.downcase
  end
end
