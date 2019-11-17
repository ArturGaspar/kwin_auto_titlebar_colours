#!/usr/bin/env python3

import argparse
import concurrent.futures
import configparser
import fnmatch
import json
import logging
import os
import shlex
import subprocess
from colorsys import hls_to_rgb, rgb_to_hls
from collections import defaultdict
from functools import partial
from itertools import chain
from operator import mul

from xdg.BaseDirectory import load_data_paths, xdg_config_home, xdg_data_home
from xdg.DesktopEntry import DesktopEntry
from xdg.IconTheme import getIconPath


logger = logging.getLogger(__name__)


CONFIG_PREFIX = "zz-auto-titlebar-colour-"
get_kwin_rule_name = get_colour_scheme_name = partial("{}{}".format,
                                                      CONFIG_PREFIX)


kwin_rules_path = os.path.join(xdg_config_home, "kwinrulesrc")


class ConfigParser(configparser.ConfigParser):
    optionxform = str

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('allow_no_value', True)
        super().__init__(*args, **kwargs)

    def write(self, *args, **kwargs):
        kwargs.setdefault('space_around_delimiters', False)
        return super().write(*args, **kwargs)


def remove_colour_schemes():
    schemes_dir = os.path.join(xdg_data_home, "color-schemes")
    pattern = get_colour_scheme_name("*")
    for filename in fnmatch.filter(os.listdir(schemes_dir),
                                   "{}.colors".format(pattern)):
        os.unlink(os.path.join(schemes_dir, filename))


def remove_kwin_rules():
    rules = ConfigParser()
    rules.read(kwin_rules_path)

    new_rules = []
    count = rules["General"].getint("count", fallback=0)
    for section in map(str, range(1, count + 1)):
        try:
            rule = dict(rules.items(section))
        except configparser.NoSectionError:
            continue
        rule_name = rules.get(section, "Description", fallback="")
        del rules[section]
        if not rule_name.startswith(CONFIG_PREFIX):
            new_rules.append(rule)

    for section, rule in enumerate(new_rules, start=1):
        rules[str(section)] = rule

    rules["General"]["count"] = str(len(new_rules))

    with open(kwin_rules_path, 'w') as f:
        rules.write(f)


def load_base_colour_scheme():
    kdeglobals = ConfigParser()
    kdeglobals.read(os.path.join(xdg_config_home, "kdeglobals"))
    base_colour_scheme = kdeglobals["General"]["ColorScheme"]

    for color_schemes_dir in load_data_paths("color-schemes"):
        for filename in os.listdir(color_schemes_dir):
            if filename == "{}.colors".format(base_colour_scheme):
                colour_scheme = ConfigParser()
                colour_scheme.read(os.path.join(color_schemes_dir, filename))
                return colour_scheme

    raise EnvironmentError(("Could not find colour scheme {}"
                            ).format(base_colour_scheme))


def find_desktop_files():
    filenames = set()
    for root, dirs, files in chain(*map(os.walk,
                                        load_data_paths("applications"))):
        for desktop_file in fnmatch.filter(files, "*.desktop"):
            if desktop_file not in filenames:
                filenames.add(desktop_file)
                yield os.path.join(root, desktop_file)


def _get_wmclass(application):
    startupwmclass = application.getStartupWMClass()
    if startupwmclass:
        return startupwmclass, 2

    tryexec = application.getTryExec()
    if tryexec:
        return os.path.basename(tryexec), 1

    exec_ = application.getExec()
    if exec_:
        cmdline = shlex.split(exec_)
        cmd = os.path.basename(cmdline[0])
        try:
            if cmd in {"sh", "xdg-su"} and cmdline[1] == "-c":
                cmdline = shlex.split(cmdline[2])
                cmd = os.path.basename(cmdline[0])
        except IndexError:
            pass
        else:
            return cmd, 0

    return None, None


def get_wmclass_icons():
    wmclass_icons = {}
    for application in map(DesktopEntry, find_desktop_files()):
        if "Screensaver" in application.getCategories():
            continue

        # Priority indicates how good a guess at WM class is. If it comes from
        # the StartupWMClass field, it is likely more accurate than a guess
        # from another entry's TryExec or Exec. In case two entries have the
        # same (guessed) class but different icons, prefer the better guess.
        wmclass, priority = _get_wmclass(application)
        if not wmclass:
            continue

        icon_name = application.getIcon()

        wmclass_icons.setdefault(priority, {})
        if wmclass_icons[priority].get(wmclass, icon_name) != icon_name:
            # If different entries pointing to different icons have the same
            # WM classes, there is no way to set different icons for both and
            # no good guess as to which one is correct.
            wmclass_icons[priority][wmclass] = None
            continue

        wmclass_icons[priority][wmclass] = icon_name

    wmclass_icons_merged = {}
    for k in set(chain(*(d.keys() for d in wmclass_icons.values()))):
        for priority in sorted(wmclass_icons.keys(), reverse=True):
            try:
                wmclass_icons_merged[k] = wmclass_icons[priority][k]
            except KeyError:
                pass
            else:
                break

    return wmclass_icons_merged


def get_colours_for_icon(icon_path):
    p = subprocess.Popen(["convert",
                          icon_path,
                          "-alpha", "off",
                          "-depth", "8",
                          "json:-"],
                         stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    data = json.loads(stdout)
    if isinstance(data, list):
        data = data[0]
    image = data["image"]
    channels = {k.lower(): v for k, v in image["channelStatistics"].items()}
    return tuple((float(channels[channel]["mean"])
                  for channel in ("red", "green", "blue")))


_to1 = partial(mul, 1 / 255)
_to255 = partial(mul, 255)


def add_colour_schemes(base_scheme, new_schemes):
    base_wm_colours = {k: tuple(map(int, v.split(",")))
                       for k, v in base_scheme.items("WM")}
    base_active_hls = rgb_to_hls(
        *map(_to1, base_wm_colours["activeBackground"])
    )
    base_inactive_hls = rgb_to_hls(
        *map(_to1, base_wm_colours["inactiveBackground"])
    )
    inactive_l_mult = (1 + (base_inactive_hls[1] / base_active_hls[1])) / 2
    inactive_s_mult = (1 + (base_inactive_hls[2] / base_active_hls[2])) / 2

    for scheme_name, icon_colour in new_schemes:
        colour_scheme = ConfigParser()

        for section in base_scheme.sections():
            colour_scheme[section] = dict(base_scheme.items(section))

        colour_scheme["General"] = {
            "Name": scheme_name
        }

        icon_hls = rgb_to_hls(*map(_to1, icon_colour))
        active_hls = (
            icon_hls[0],
            (icon_hls[1] + base_active_hls[1]) / 2,
            min(icon_hls[2] * 1.5, 1)
        )
        inactive_hls = (
            icon_hls[0],
            min(inactive_l_mult * active_hls[1], 1),
            min(inactive_s_mult * active_hls[2], 1)
        )
        wm_colours = base_wm_colours.copy()
        wm_colours.update({
            "activeBackground": tuple(map(_to255, hls_to_rgb(*active_hls))),
            "inactiveBackground": tuple(map(_to255, hls_to_rgb(*inactive_hls)))
        })
        colour_scheme["WM"] = {k: ",".join(map(str, map(int, v)))
                               for k, v in wm_colours.items()}

        path = os.path.join(xdg_data_home, "color-schemes",
                            "{}.colors".format(scheme_name))
        with open(path, 'w') as f:
            colour_scheme.write(f)


def update_kwin_rules(updates):
    rules = ConfigParser()
    rules.read(kwin_rules_path)

    count = rules["General"].getint("count", fallback=0)
    known_rules = {}
    for i in range(1, count + 1):
        known_rules[rules.get(str(i), "Description", fallback=None)] = i

    for wmclass, colour_scheme in updates:
        rule_name = get_kwin_rule_name(wmclass)
        is_new = rule_name in known_rules
        try:
            rule_index = known_rules[rule_name]
            rule = rules[str(rule_index)]
        except KeyError:
            if colour_scheme is None:
                # Do not create a new rule if there is no colour scheme for it.
                continue
            count += 1
            rule_index = count
            rule = {
                "Description": rule_name,
                "decocolorrule": "2"
            }

        rule["wmclass"] = wmclass
        rule["wmclassmatch"] = "1"
        if "decocolorrule" not in rule:
            # Disabled by user.
            continue
        if colour_scheme is not None:
            rule["decocolor"] = colour_scheme
            rule["decocolorrule"] = "2"
        else:
            rule["decocolorrule"] = "1"

        rules[str(rule_index)] = dict(rule)

    rules["General"]["count"] = str(count)

    with open(kwin_rules_path, 'w') as f:
        rules.write(f)


def update_application_colours(executor):
    base_colour_scheme = load_base_colour_scheme()

    colour_scheme_futures = {}
    wmclass_colour_schemes = defaultdict(list)

    kdeglobals = ConfigParser()
    kdeglobals.read(os.path.join(xdg_config_home, "kdeglobals"))
    icon_theme = kdeglobals["Icons"]["Theme"]

    for wmclass, icon_name in get_wmclass_icons().items():
        if icon_name is None:
            colour_scheme = None
        else:
            icon_path = getIconPath(icon_name, theme=icon_theme)
            if icon_path is None or not os.path.isfile(icon_path):
                colour_scheme = None
            else:
                colour_scheme = get_colour_scheme_name(
                    icon_name.replace(os.sep, "_").replace(".", "_")
                )
                future = executor.submit(get_colours_for_icon, icon_path)
                colour_scheme_futures[future] = (colour_scheme, icon_path)

        wmclass_colour_schemes[colour_scheme].append(wmclass)

    remove_colour_schemes()

    broken_colour_schemes = {None}
    new_colour_schemes = []
    for future in concurrent.futures.as_completed(colour_scheme_futures):
        colour_scheme, icon_path = colour_scheme_futures[future]
        try:
            icon_colours = future.result()
        except Exception:
            logger.exception("Error processing icon: {}".format(icon_path))
            broken_colour_schemes.add(colour_scheme)
        else:
            new_colour_schemes.append((colour_scheme, icon_colours))
    add_colour_schemes(base_colour_scheme, new_colour_schemes)

    kwin_rule_updates = []
    for colour_scheme, wmclasses in wmclass_colour_schemes.items():
        if colour_scheme in broken_colour_schemes:
            colour_scheme = None
        for wmclass in wmclasses:
            kwin_rule_updates.append((wmclass, colour_scheme))
    update_kwin_rules(sorted(kwin_rule_updates))


def uninstall():
    remove_colour_schemes()
    remove_kwin_rules()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()

    if args.uninstall:
        uninstall()
    else:
        with concurrent.futures.ProcessPoolExecutor() as executor:
            update_application_colours(executor)

    subprocess.call(["dbus-send", "--type=signal", "--dest=org.kde.KWin",
                     "/KWin", "org.kde.KWin.reloadConfig"])
