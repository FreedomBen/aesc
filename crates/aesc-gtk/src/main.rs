//! `aesc-gtk` binary entry point. All logic lives in the library crate
//! (`aesc_gtk`); this is a thin launcher. See
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md`.

fn main() -> gtk::glib::ExitCode {
    aesc_gtk::run()
}
