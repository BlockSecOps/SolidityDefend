# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "1.10.23"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-macos-aarch64.tar.gz"
      sha256 "d4c442b1f34c2977a9dea9156c407a391ca0b4ab1815ed63ba8930cd2fe5b8d6"
    end
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-macos-x86_64.tar.gz"
      sha256 "bd991aaa6561c77f1e43c9c6b8f2677d3a64917da0a4a66f61672a2a742ab7d2"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-linux-x86_64.tar.gz"
      sha256 "31e1dbf9942a6eba7418473d876335244c8c22ff639d011ad80e863147adff32"
    end
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.23/soliditydefend-v1.10.23-linux-aarch64.tar.gz"
      sha256 "5c1d6c086c4efa88fa29082066c438e106864d8e48d5697733567bc52235bfa2"
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
