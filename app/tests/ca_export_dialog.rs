#![cfg(target_os = "linux")]

use std::path::PathBuf;

#[test]
#[ignore = "requires the isolated portal fixture: python3 scripts/test-ca-export-dialog.py"]
fn ca_save_dialog_works_without_a_tokio_runtime() {
    // The egui event thread has no active Tokio runtime, even while the proxy's
    // background runtime exists. Exercise the real native dialog backend here.
    assert!(tokio::runtime::Handle::try_current().is_err());
    let expected = PathBuf::from(
        std::env::var_os("PRIVAXY_DIALOG_TEST_PATH").expect("run the portal fixture script"),
    );
    let selected = rfd::FileDialog::new()
        .set_file_name("privaxy-desktop-ca.crt")
        .save_file();
    assert_eq!(selected, Some(expected));

    let cancelled = rfd::FileDialog::new()
        .set_file_name("privaxy-desktop-ca.crt")
        .save_file();
    assert_eq!(cancelled, None);
}
