{ }:

let
  base = import ./base.nix { };

in

with import <nixpkgs> {};

buildEnv {
  name = "dev-env";
  ignoreCollisions = true;
  paths = [
    (openldap.override { cyrus_sasl = null; openssl = null; })
    python27Packages.ldap
  ] ++ base.paths27;
}