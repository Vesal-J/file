// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

fn main() {
    if let Err(error) = uu_file::run(std::env::args_os()) {
        eprintln!("file: {error}");
        std::process::exit(1);
    }
}
