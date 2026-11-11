fn main() {
    // `sqlx::migrate!` embeds the migration files at compile time; make cargo
    // rebuild when a migration is added, removed or changed.
    println!("cargo:rerun-if-changed=migrations");
}
