fn main() {
    // Windows-specific PE version resources and RT_MANIFEST embedding
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set("CompanyName", "Abdelrahman Aboelsaad");
        res.set("ProductName", "Smart Windows Cleaner");
        res.set("FileDescription", "Smart Windows Cleaner Core Native Engine");
        res.set("ProductVersion", "1.0.1");
        res.set("FileVersion", "1.0.1.0");
        res.set("OriginalFilename", "smart-cleaner-core.exe");
        res.set("LegalCopyright", "Copyright © 2026 Abdelrahman Aboelsaad");
        res.set_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#);
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=Failed to compile Windows PE resources: {}", e);
        }
    }
}
