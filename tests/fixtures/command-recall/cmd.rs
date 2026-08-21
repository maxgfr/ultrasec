use std::process::Command;

fn handler(q: String) {
    Command::new("sh").arg("-c").arg(q).output().unwrap();
}
