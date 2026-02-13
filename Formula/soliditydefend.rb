# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "1.10.24"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.24/soliditydefend-v1.10.24-macos-aarch64.tar.gz"
      sha256 "63a623651f19931ccc6c5b8f238e497c0e065d15189187b383fddb951ff26f80"
    end
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.24/soliditydefend-v1.10.24-macos-x86_64.tar.gz"
      sha256 "3832f9b7709789d04ca99f36d3de762db0f7653c35b9a770d23aed06238002e2"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.24/soliditydefend-v1.10.24-linux-x86_64.tar.gz"
      sha256 "f097cf54bf4b6f487672e0376314a07994186bed482263feca25ef00ef4638de"
    end
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.10.24/soliditydefend-v1.10.24-linux-aarch64.tar.gz"
      sha256 "45c39c9b9c2634d8abc48fec3931ccb9b08ef17b439f63f0b951f92b4966eca6"
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
    assert_match "soliditydefend 1.10.24", shell_output("#{bin}/soliditydefend --version 2>&1", 1)
    assert_match "Usage:", shell_output("#{bin}/soliditydefend --help 2>&1", 1)
    output = shell_output("#{bin}/soliditydefend --list-detectors 2>&1")
    assert_match "detector", output.downcase
  end
end
