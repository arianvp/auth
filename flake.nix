{
  description = "auth";

  outputs = { self, nixpkgs }: {
    packages.aarch64-darwin.auth = nixpkgs.legacyPackages.aarch64-darwin.callPackage ./. { };
    packages.aarch64-darwin.default = self.packages.aarch64-darwin.auth;
  };
}
