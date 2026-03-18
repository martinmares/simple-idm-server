fn main() {
    // Ensure sqlx::migrate! embedded migrations are refreshed when migration files change.
    println!("cargo:rerun-if-changed=../../migrations");
}
