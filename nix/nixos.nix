# NixOS module: the root sampler behind the memory section's per-process table.
self: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.rstat.processMemory;
in {
  options.services.rstat.processMemory = {
    enable = lib.mkEnableOption "the root sampler for rstat's per-process memory table";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The rstat package.";
    };
    interval = lib.mkOption {
      type = lib.types.str;
      default = "60s";
      description = "Time between samples, as a systemd time span.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.rstat-process-memory = {
      description = "Sample proportional process memory for rstat";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/rstat sample-process-memory /run/waybar-memory-processes.json";
        Nice = 19;
        TimeoutStartSec = 20;
        UMask = "0022";
      };
    };
    systemd.timers.rstat-process-memory = {
      wantedBy = ["timers.target"];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitInactiveSec = cfg.interval;
      };
    };
  };
}
