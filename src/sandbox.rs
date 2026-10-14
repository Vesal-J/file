// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::config::Config;

pub fn enter_sandbox(config: &Config) {
    if config.no_sandbox {
        return;
    }

    // On Linux or other platforms, sandboxing is optional and non-fatal
}
