//! The Windows resource: the icon the shell shows for the executable, and the version information
//! `propsheet` reads.
//!
//! A portable tool has no installer to write these, so they have to be baked in. Everything here is
//! a build-time concern; nothing at runtime depends on it, and a platform without a resource
//! compiler simply gets no resource.

fn main() {
    println!("cargo:rerun-if-changed=assets/winfw-mcp.ico");

    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();

        // The version fields come from `Cargo.toml` unless they are set here, and winresource
        // already fills those in from `CARGO_PKG_VERSION`. What it cannot know is the prose.
        resource.set("ProductName", "winfw-mcp");
        resource.set(
            "FileDescription",
            "Portable Windows firewall with an MCP endpoint",
        );
        resource.set("OriginalFilename", "winfw-mcp.exe");
        resource.set("LegalCopyright", "Copyright (c) prinzalx");
        resource.set("CompanyName", "winfw-mcp");
        resource.set_icon("assets/winfw-mcp.ico");

        // A resource the compiler refuses is worth more than a warning: the executable would
        // silently go back to the generic icon it had before.
        if let Err(error) = resource.compile() {
            panic!("could not build the Windows resource: {error}");
        }
    }
}
