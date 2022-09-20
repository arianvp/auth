{
  description = "auth";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages;

      packages = { pkgs, selfPackages }: {
        default = selfPackages.auth;
        auth = pkgs.buildGoModule {
          name = "auth";
          src = ./.;
          vendorHash = null;
        };
      };
    in
    {
      packages = {
        aarch64-darwin = packages {
          pkgs = nixpkgs.legacyPackages.aarch64-darwin;
          selfPackages = self.packages.aarch64-darwin;
        };
        x86_64-linux = packages {
          pkgs = nixpkgs.legacyPackages.x86_64-linux;
          selfPackages = self.packages.x86_64-linux;
        };
      };
    };
}
