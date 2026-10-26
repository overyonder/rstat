# Home Manager module: the rstat daemon, its configuration, and Waybar module definitions to use in
# programs.waybar.settings.
self: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.programs.rstat;
  sections = import ./sections.nix;
  colorOption = default: description:
    lib.mkOption {
      type = lib.types.str;
      inherit default description;
    };
  sectionOptions = name: groups:
    {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether to serve the ${name} section.";
      };
    }
    // lib.mapAttrs (_: description:
      lib.mkOption {
        type = lib.types.bool;
        default = true;
        inherit description;
      })
    groups;
  settings =
    {
      interval_ms = cfg.intervalMs;
      inherit (cfg) colors;
      alerts =
        map (alert: {
          inherit (alert) figure above command;
          sustain_seconds = alert.sustainSeconds;
          repeat_seconds = alert.repeatSeconds;
        })
        cfg.alerts;
    }
    // lib.mapAttrs (name: _: cfg.${name}) sections;
  configFile = (pkgs.formats.toml {}).generate "rstat.toml" settings;
in {
  options.programs.rstat =
    {
      enable = lib.mkEnableOption "the rstat system monitor daemon for Waybar";
      package = lib.mkOption {
        type = lib.types.package;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        description = "The rstat package.";
      };
      intervalMs = lib.mkOption {
        type = lib.types.ints.between 100 60000;
        default = 1000;
        description = "How often watched sections are sampled, in milliseconds.";
      };
      colors = {
        ok = colorOption "#a6e3a1" "Colour of figures within normal range.";
        warning = colorOption "#fab387" "Colour of figures showing strain.";
        critical = colorOption "#f38ba8" "Colour of figures showing severe strain.";
        label = colorOption "#7f849c" "Colour of labels.";
        value = colorOption "#cdd6f4" "Colour of descriptive figures.";
        heading = colorOption "#89b4fa" "Colour of tooltip headings.";
      };
      alerts = lib.mkOption {
        default = [];
        description = ''
          Commands to run when a figure stays above a threshold. Each receives a JSON description on
          standard input: the figure, its value and threshold, and the process sessions contributing
          most to the strain. The figure's section is sampled whether or not Waybar watches it.
        '';
        type = lib.types.listOf (lib.types.submodule {
          options = {
            figure = lib.mkOption {
              type = lib.types.enum [
                "cpu.load"
                "cpu.pressure"
                "memory.pressure_some"
                "memory.pressure_full"
                "disks.queue"
                "disks.pressure_some"
                "disks.pressure_full"
                "network.nas_wait"
              ];
              description = "The figure to watch.";
            };
            above = lib.mkOption {
              type = lib.types.number;
              description = "The threshold; pressures are percentages, load and queues are task or request counts.";
            };
            sustainSeconds = lib.mkOption {
              type = lib.types.ints.unsigned;
              default = 5;
              description = "How long the figure must stay above the threshold before the command runs.";
            };
            repeatSeconds = lib.mkOption {
              type = lib.types.ints.unsigned;
              default = 600;
              description = "How long after running the command it may run again while the figure stays above.";
            };
            command = lib.mkOption {
              type = lib.types.nonEmptyListOf lib.types.str;
              description = "The program and its arguments.";
            };
          };
        });
      };
      waybarModules = lib.mkOption {
        type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
        readOnly = true;
        description = ''
          Waybar custom module definitions for each enabled section, keyed by section name. Merge them
          into a bar, adding a format: `"custom/cpu" = config.programs.rstat.waybarModules.cpu // { format = " {}"; };`
        '';
      };
    }
    // lib.mapAttrs sectionOptions sections
    // {
      gpu =
        sectionOptions "gpu" sections.gpu
        // {
          devices = lib.mkOption {
            type = lib.types.listOf lib.types.ints.unsigned;
            default = [];
            description = "NVML indices of the GPUs to show; empty shows every GPU.";
          };
        };
    };

  config = lib.mkIf cfg.enable {
    programs.rstat.waybarModules = lib.mapAttrs (name: _: {
      exec = "${cfg.package}/bin/rstat watch ${name}";
      return-type = "json";
      # The daemon sends a line when the section changes; Waybar restarts the watcher if it exits.
      restart-interval = 5;
    }) (lib.filterAttrs (name: _: cfg.${name}.enable) sections);

    systemd.user.services.rstat = {
      Unit = {
        Description = "rstat system monitor for Waybar";
        PartOf = ["graphical-session.target"];
        X-Restart-Triggers = ["${configFile}"];
      };
      Service = {
        ExecStart = "${cfg.package}/bin/rstat daemon --config ${configFile}";
        Restart = "on-failure";
      };
      Install.WantedBy = ["graphical-session.target"];
    };
  };
}
