# Formula for Homebrew installation of SolidityDefend
class Soliditydefend < Formula
  desc "High-performance static analysis security tool for Solidity smart contracts"
  homepage "https://github.com/BlockSecOps/SolidityDefend"
  version "2.0.1"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.1/soliditydefend-v2.0.1-macos-aarch64.tar.gz"
      sha256 "55f85ee2294a485eb7d0bb48d9ab505d702a5055a2e4268c330e5cb435758714"
    end
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.1/soliditydefend-v2.0.1-macos-x86_64.tar.gz"
      sha256 "320f4fd56f36e1d76bb2e32c18bb2cd1d63a9c12b81147e092425d486fda76a1"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.1/soliditydefend-v2.0.1-linux-x86_64.tar.gz"
      sha256 "d36ad8c83e9508a5050d6a755dfddc1ffffb0beacf7a12a8208e93913610fd71"
    end
    on_arm do
      url "https://github.com/BlockSecOps/SolidityDefend/releases/download/v2.0.1/soliditydefend-v2.0.1-linux-aarch64.tar.gz"
      sha256 "578cbb4d25dd61ad2abfed80d771e96aead09e3812243d33b497b6abb953bc47"
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
    assert_match "soliditydefend 2.0.1", shell_output("#{bin}/soliditydefend --version 2>&1", 1)
    assert_match "Usage:", shell_output("#{bin}/soliditydefend --help 2>&1", 1)
    output = shell_output("#{bin}/soliditydefend --list-detectors 2>&1")
    assert_match "detector", output.downcase
  end
end
