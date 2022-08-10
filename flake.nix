{
  description = "auth";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.aarch64-darwin;
    in
    {

      packages.aarch64-darwin.default = self.packages.aarch64-darwin.auth;
      packages.aarch64-darwin.auth = pkgs.buildGoModule {
        name = "auth";
        src = ./.;
	vendorHash = "sha256-pQpattmS9VmO3ZIQUFn66az8GSmB4IvYhTTCFn6SUmo=";
      };
    };
}
