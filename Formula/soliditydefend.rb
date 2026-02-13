# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "2.0.0"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.0/soliditydefend-v2.0.0-macos-aarch64.tar.gz"
      sha256 "9c71c38a37ec856194af498519122a1a9d5e0dadfea7e5488857573202597fbb"
    end
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.0/soliditydefend-v2.0.0-macos-x86_64.tar.gz"
      sha256 "fa187b7d2f39392847343265c7aa850aefe0fc1d6b9143af21234adf8d7d2eed"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.0/soliditydefend-v2.0.0-linux-x86_64.tar.gz"
      sha256 "13b980eecfe4369b0a154609092347bda5b700b9c535b4b92fb4c86830090df8"
    end
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.0/soliditydefend-v2.0.0-linux-aarch64.tar.gz"
      sha256 "026175b6024cd381b6b55632daf9e6c32acb90db0419cbb640600fe612a76094"
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
    assert_match "soliditydefend 2.0.0", shell_output("#{bin}/soliditydefend --version 2>&1", 1)
    assert_match "Usage:", shell_output("#{bin}/soliditydefend --help 2>&1", 1)
    output = shell_output("#{bin}/soliditydefend --list-detectors 2>&1")
    assert_match "detector", output.downcase
  end
end
