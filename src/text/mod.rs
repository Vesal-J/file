// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

pub mod ascmagic;
pub mod encoding;

pub use ascmagic::{test_text, TextResult};
pub use encoding::{detect_encoding, Charset, LineCharacteristics};
