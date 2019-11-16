#!/usr/bin/env python3

import colorsys
import concurrent.futures
import configparser
import fnmatch
import json
import logging
import os
import shlex
import subprocess
from collections import defaultdict
from functools import partial
from itertools import chain

from xdg.BaseDirectory import load_data_paths, xdg_config_home, xdg_data_home
from xdg.DesktopEntry import DesktopEntry
from xdg.IconTheme import getIconPath


logger = logging.getLogger(__name__)


CONFIG_PREFIX = "zz-auto-titlebar-colour-"
get_kwin_rule_name = get_colour_scheme_name = partial("{}{}".format,
                                                      CONFIG_PREFIX)


class ConfigParser(configparser.ConfigParser):
    optionxform = str

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('allow_no_value', True)
        super(ConfigParser, self).__init__(*args, **kwargs)

    def write(self, *args, **kwargs):
        kwargs.setdefault('space_around_delimiters', False)
        return super(ConfigParser, self).write(*args, **kwargs)



def find_desktop_files():
    filenames = set()
    for root, dirs, files in chain(*map(os.walk,
                                        load_data_paths("applications"))):
        for desktop_file in fnmatch.filter(files, "*.desktop"):
            if desktop_file not in filenames:
                filenames.add(desktop_file)
                yield os.path.join(root, desktop_file)


def load_base_colours():
    kdeglobals = ConfigParser()
    kdeglobals.read(os.path.join(xdg_config_home, "kdeglobals"))
    base_colour_scheme = kdeglobals["General"]["ColorScheme"]

    for color_schemes_dir in load_data_paths("color-schemes"):
        for filename in os.listdir(color_schemes_dir):
            if filename == "{}.colors".format(base_colour_scheme):
                colour_scheme = ConfigParser()
                colour_scheme.read(os.path.join(color_schemes_dir, filename))
                return {k: tuple(map(int, v.split(',')))
                        for k, v in colour_scheme["WM"].items()}

    raise EnvironmentError(("Could not find colour scheme {}"
                            ).format(base_colour_scheme))


def get_colours_for_icon(icon_path):
    p = subprocess.Popen(["convert",
                          icon_path,
                          "-alpha", "off",
                          "-depth", "8",
                          "json:-"],
                         stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    data = json.loads(stdout)
    return tuple((data[0]["image"]["channelStatistics"][channel]["mean"]
                  for channel in ("Red", "Green", "Blue")))


def remove_colour_schemes():
    schemes_dir = os.path.join(xdg_data_home, "color-schemes")
    pattern = get_colour_scheme_name("*")
    for filename in fnmatch.filter(os.listdir(schemes_dir),
                                   "{}.colors".format(pattern)):
        os.unlink(os.path.join(schemes_dir, filename))


def add_colour_scheme(base, name, icon_colour):
    colour_scheme = ConfigParser()
    colour_scheme["General"] = {
        "Name": name
    }

    icon_h, icon_s, icon_v = colorsys.rgb_to_hsv(*icon_colour)
    colours = base.copy()
    for k in ["activeBackground", "inactiveBackground"]:
        h, s, v = colorsys.rgb_to_hsv(*colours[k])
        h = icon_h
        s = (icon_s * 4 + s) / 5
        v = (icon_v * 4 + v) / 5
        colours[k] = tuple(map(int, colorsys.hsv_to_rgb(h, s, v)))

    colour_scheme["WM"] = {k: ",".join(map(str, v))
                           for k, v in colours.items()}

    path = os.path.join(xdg_data_home, "color-schemes",
                        "{}.colors".format(name))
    with open(path, 'w') as f:
        colour_scheme.write(f)


def update_kwin_rules(updates):
    kwin_rules_path = os.path.join(xdg_config_home, "kwinrulesrc")

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


def get_wmclass(application):
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
        wmclass, priority = get_wmclass(application)
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


def update_application_colours(executor):
    base_colours = load_base_colours()

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
                colour_scheme_futures[future] = colour_scheme

        wmclass_colour_schemes[colour_scheme].append(wmclass)

    remove_colour_schemes()

    broken_colour_schemes = {None}

    for future in concurrent.futures.as_completed(colour_scheme_futures):
        colour_scheme = colour_scheme_futures[future]
        try:
            icon_colours = future.result()
        except Exception:
            logger.exception("Error processing icon {}".format(icon_name))
            broken_colour_schemes.add(colour_scheme)
        else:
            add_colour_scheme(base_colours, colour_scheme, icon_colours)

    kwin_rule_updates = []
    for colour_scheme, wmclasses in wmclass_colour_schemes.items():
        if colour_scheme in broken_colour_schemes:
            colour_scheme = None
        for wmclass in wmclasses:
            kwin_rule_updates.append((wmclass, colour_scheme))
    update_kwin_rules(sorted(kwin_rule_updates))

    subprocess.call(["dbus-send", "--type=signal", "--dest=org.kde.KWin",
                     "/KWin", "org.kde.KWin.reloadConfig"])


if __name__ == "__main__":
    with concurrent.futures.ProcessPoolExecutor() as executor:
        update_application_colours(executor)