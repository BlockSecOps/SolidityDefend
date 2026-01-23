# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "1.10.5"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.5/soliditydefend-v1.10.5-darwin-arm64.tar.gz"
      sha256 "07e458f4268cc8aec7c95a6a9e6a68c2b0a5927f5e8fcc6e8e0c04ec6574fe98"
    else
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.5/soliditydefend-v1.10.5-darwin-x86_64.tar.gz"
      sha256 "1808f1fbeb0e9dc8b67529f294f30a85fe12eeda84e50b1f8ce9ef9644a42537"
    end
  end

  on_linux do
    url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.5/soliditydefend-v1.10.5-linux-x86_64.tar.gz"
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
    assert_match "soliditydefend 1.10.5", shell_output("#{bin}/soliditydefend --version")

    # Test help command
    assert_match "USAGE:", shell_output("#{bin}/soliditydefend --help")

    # Test list-detectors command
    assert_match "detectors", shell_output("#{bin}/soliditydefend --list-detectors")
  end
end
