#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yarAnalyzer
# Yara Rule Statistics and Analysis
#
# Florian Roth
#
# DISCLAIMER - USE AT YOUR OWN RISK.

import sys
import os
import argparse
import scandir
import traceback
import yara
import hashlib
import re
import stat
import datetime
import platform
import binascii
from prettytable import PrettyTable

def scan_path(path, rule_sets, num_first_bytes=6):

    # Startup
    log("INFO","Scanning %s ...  " % path)

    # Counter
    c = 0

    # Get application path
    app_path = get_application_path()

    for root, directories, files in scandir.walk(path, onerror=walk_error, followlinks=False):

        # Loop through files
        for filename in files:
            try:

                # Get the file and path
                filePath = os.path.join(root,filename)

                # Relative Path
                relPath = filePath[len(path):]

                fileSize = os.stat(filePath).st_size

                if fileSize > ( args.m * 1024 * 1024):
                    continue

                # Prepare the file matches
                file_stats[relPath] = {}
                file_stats[relPath]["matches"] = {}
                file_stats[relPath]["size"] = fileSize

                # Set fileData to an empty value
                fileData = ""

                # Hash Check -------------------------------------------------------
                # Do the check
                md5 = "-"
                sha1 = "-"
                sha256 = "-"

                fileData = read_file_data(filePath)

                if len(fileData) > 1:
                    file_stats[relPath]["firstBytes_Hex"] = "%s" % fileData[:num_first_bytes].encode("hex")
                    file_stats[relPath]["firstBytes_Ascii"] = "%s" % remove_non_ascii(fileData[:num_first_bytes])
                else:
                    file_stats[relPath]["firstBytes_Hex"] = "-"
                    file_stats[relPath]["firstBytes_Ascii"] = "-"

                md5, sha1, sha256 = generate_hashes(fileData)
                file_stats[relPath]["md5"] = md5
                file_stats[relPath]["sha1"] = sha1
                file_stats[relPath]["sha256"] = sha256

                log("DEBUG", "MD5: %s SHA1: %s SHA256: %s FILE: %s" % ( md5, sha1, sha256, filePath ))

                if args.printAll:
                    print "FILE: %s" % ( filePath )

                # Yara Check -------------------------------------------------------

                # Scan with yara
                try:
                    for rules in rule_sets:

                        # Yara Rule Match -------------------------------------
                        matches = rules.match(data=fileData,
                                              externals= {
                                                  'filename': filename.lower(),
                                                  'filepath': filePath.lower()
                                              })

                        # If matched ------------------------------------------
                        if matches:
                            for match in matches:

                                description = "not set"

                                # Built-in rules have meta fields (cannot be expected from custom rules)
                                if hasattr(match, 'meta'):

                                    if 'description' in match.meta:
                                        description = match.meta['description']

                                # Matching strings
                                matched_strings = ""
                                if hasattr(match, 'strings'):
                                    # Get matching strings
                                    matched_strings = get_string_matches(match.strings)

                                # Add the stats
                                file_stats[relPath]["matches"][match.rule] = matched_strings
                                rule_stats[match.rule]["files"].append(relPath)

                except Exception, e:
                    if args.debug:
                        traceback.print_exc()

            except Exception, e:
                if args.debug:
                    traceback.print_exc()


def read_file_data(filePath):
    fileData = ""
    try:
        # Read file complete
        with open(filePath, 'rb') as f:
            fileData = f.read()
    except Exception, e:
        log("DEBUG", "Cannot open file %s (access denied)" % filePath)
    finally:
        return fileData


def generate_hashes(filedata):
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(filedata)
        sha1.update(filedata)
        sha256.update(filedata)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception, e:
        traceback.print_exc()
        return 0, 0, 0


def get_string_matches(strings):
    try:
        string_matches = []
        matching_strings = ""
        for string in strings:
            # print string
            extract = string[2]
            if not extract in string_matches:
                string_matches.append(extract)

        string_num = 1
        for string in string_matches:
            # UNICDOE
            if '\0' in string:
                matching_strings += " Str" + str(string_num) + "(U): " + remove_non_ascii(remove_binary_zero(string))
            else:
            # ASCII
                matching_strings += " Str" + str(string_num) + "(A): " + remove_non_ascii(remove_binary_zero(string))
            string_num += 1

        # Limit string
        if len(matching_strings) > 140:
            matching_strings = matching_strings[:140] + " ... (truncated)"

        return matching_strings.lstrip(" ")
    except:
        traceback.print_exc()


def walk_error(err):
    if "Error 3" in str(err):
        log("ERROR", str(err))
    if args.debug:
        traceback.print_exc()


def initialize_yara_rules(rule_path, rules_extension):

    yara_rules = []
    filename_dummy = ""
    filepath_dummy = ""

    # Signature are located in a path
    if os.path.isdir(rule_path):
        try:
            for root, directories, files in scandir.walk(rule_path, onerror=walk_error, followlinks=False):
                for file in files:
                    try:

                        # Full Path
                        yaraRuleFile = os.path.join(root, file)

                        # Skip hidden, backup or system related files
                        if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                            continue

                        # Extension
                        extension = os.path.splitext(file)[1].lower()

                        # Encrypted
                        if extension == ".{0}".format(rules_extension):
                            try:
                                compiledRules = yara.compile(yaraRuleFile, externals= {
                                                                  'filename': filename_dummy,
                                                                  'filepath': filepath_dummy
                                                              })
                                yara_rules.append(compiledRules)
                                log("INFO", "Initialized Yara rules from %s" % file)
                            except Exception, e:
                                log("ERROR", "Error in Yara file: %s" % file)
                                if args.debug:
                                    traceback.print_exc()

                    except Exception, e:
                        log("ERROR", "Error reading signature file %s ERROR: %s" % yaraRuleFile)
                        if args.debug:
                            traceback.print_exc()

        except Exception, e:
            log("ERROR", "Error reading signature folder /signatures/")
            if args.debug:
                traceback.print_exc()

    # Is a signature file
    else:
        try:
            compiledRules = yara.compile(rule_path, externals= {
                                              'filename': filename_dummy,
                                              'filepath': filepath_dummy
                                          })
            yara_rules.append(compiledRules)
            log("INFO", "Initialized Yara rules from %s" % rule_path)
        except Exception, e:
            log("ERROR", "Error in Yara file: %s" % rule_path)
            if args.debug:
                traceback.print_exc()

    return yara_rules


def generate_yara_stats_structure(yara_rules):
    for rule_set in yara_rules:
        for rule in rule_set:
            rule_stats[rule.identifier] = {}
            rule_stats[rule.identifier]["files"] = []
            rule_stats[rule.identifier]["count"] = 0


def remove_binary_zero(string):
    return re.sub(r'\x00','',string)


def get_application_path():
    try:
        application_path = ""
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        elif __file__:
            application_path = os.path.dirname(__file__)
        if application_path != "":
            # Working directory change skipped due to the function to create TXT, CSV and HTML file on the local file
            # system when thor is started from a read only network share
            # os.chdir(application_path)
            pass
        if application_path == "":
            application_path = os.path.dirname(os.path.realpath(__file__))
        if "~" in application_path and not isLinux:
            # print "Trying to translate"
            # print application_path
            application_path = win32api.GetLongPathName(application_path)
        #if args.debug:
        #    log("DEBUG", "Application Path: %s" % application_path)
        return application_path
    except Exception, e:
        log("ERROR","Error while evaluation of application path")


def log(mes_type, message):

    if not args.debug and mes_type == "DEBUG":
        return

    # Prepare Message
    orig_message = message
    message = remove_non_ascii(message)

    print "[%s]: %s" % (mes_type, message)


def remove_non_ascii(string, stripit=False):
    nonascii = "error"

    try:
        try:
            # Handle according to the type
            if isinstance(string, unicode) and not stripit:
                nonascii = string.encode('unicode-escape')
            elif isinstance(string, str) and not stripit:
                nonascii = string.decode('utf-8', 'replace').encode('unicode-escape')
            else:
                try:
                    nonascii = string.encode('raw_unicode_escape')
                except Exception, e:
                    nonascii = str("%s" % string)

        except Exception, e:
            # traceback.print_exc()
            # print "All methods failed - removing characters"
            # Generate a new string without disturbing characters
            nonascii = "".join(i for i in string if ord(i)<127 and ord(i)>31)

    except Exception, e:
        traceback.print_exc()
        pass

    return nonascii


def get_platform_full():
    type_info = ""
    try:
        type_info = "%s PROC: %s ARCH: %s" % ( " ".join(platform.win32_ver()), platform.processor(), " ".join(platform.architecture()))
    except Exception, e:
        type_info = " ".join(platform.win32_ver())
    return type_info


def pretty_print(no_empty=False, max_string=26):

    x = PrettyTable(["File", "Size", "HHex", "HAscii", "Rule Matches"])
    x.padding_width = 1
    x.align["File"] = "l" # Left align rules
    x.align["Size"] = "l" # Left align rules
    x.align["HAscii"] = "l" # Left align rules
    x.align["HHex"] = "l" # Left align rules
    x.align["Rule Matches"] = "l" # Left align rules

    for relPath in file_stats:

        if no_empty and len(file_stats[relPath]["matches"]) < 1:
            continue

        # Add line
        rules = "\n".join(rule[:max_string] for rule in file_stats[relPath]["matches"])

        x.add_row([
            relPath[:max_string],
            file_stats[relPath]["size"],
            file_stats[relPath]["firstBytes_Hex"],
            file_stats[relPath]["firstBytes_Ascii"],
            rules
        ])

    print x #get_string(sortby="File")

    x = PrettyTable(["Rule", "Match Count", "Files"])
    x.padding_width = 1
    x.align["Rule"] = "l" # Left align rules
    x.align["Match Count"] = "l" # Left align rules
    x.align["Files"] = "l" # Left align rules

    for rule in rule_stats:

        if no_empty and len(rule_stats[rule]["files"]) < 1:
            continue

        rule_name = rule[:max_string]

        # Add line
        files = "\n".join(file[:max_string] for file in rule_stats[rule]["files"])

        x.add_row([
            rule_name,
            len(rule_stats[rule]["files"]),
            files
        ])
    print x


def save_stats(no_empty=False, identifier="yarAnalyzer", excel_patch=False):

    with open("{0}_file_stats.csv".format(identifier), "w") as f_file:

        f_file.write("File;Extension;Size;First Bytes in Hex;First Bytes in ASCII;MD5;SHA1;SHA256;Rule Match;Matched Strings\n")

        for relPath in file_stats:

            if no_empty and len(file_stats[relPath]["matches"]) < 1:
                continue

            # Extension
            extension = os.path.splitext(relPath)[1].lower()

            # Excel Patch
            excel_addon = "=" if excel_patch else ""

            # Write the line
            try:
                # Files with matches
                if len(file_stats[relPath]["matches"]) > 0:
                    for rule in file_stats[relPath]["matches"]:
                        matched_strings = file_stats[relPath]["matches"][rule]
                        f_file.write("{0};{1};{2};{10}\"{3}\";{10}\"{4}\";{5};{6};{7};{8};{10}\"{9}\"\n".format(relPath,
                                                                                extension,
                                                                                file_stats[relPath]["size"],
                                                                                file_stats[relPath]["firstBytes_Hex"],
                                                                                file_stats[relPath]["firstBytes_Ascii"],
                                                                                file_stats[relPath]["md5"],
                                                                                file_stats[relPath]["sha1"],
                                                                                file_stats[relPath]["sha256"],
                                                                                rule,
                                                                                matched_strings,
                                                                                excel_addon
                                                                                ))
                # Files with no matches
                else:
                    f_file.write("{0};{1};{2};{10}\"{3}\";{10}\"{4}\";{5};{6};{7};{8};{10}\"{9}\"\n".format(relPath,
                                                                            extension,
                                                                            file_stats[relPath]["size"],
                                                                            file_stats[relPath]["firstBytes_Hex"],
                                                                            file_stats[relPath]["firstBytes_Ascii"],
                                                                            file_stats[relPath]["md5"],
                                                                            file_stats[relPath]["sha1"],
                                                                            file_stats[relPath]["sha256"],
                                                                            "-",
                                                                            "-",
                                                                            excel_addon
                                                                            ))

            except Exception,e:
                print "Error while formatting line - skipping it - CSV results may be incomplete"

    with open("{0}_rule_stats.csv".format(identifier), "w") as r_file:

        r_file.write("Rule;Number of Matches;File;MD5;SHA1;SHA256\n")

        for rule in rule_stats:

            if no_empty and len(rule_stats[rule]["files"]) < 1:
                continue

            # Write the line
            try:
                # Rules with matches
                if len(rule_stats[rule]["files"]) > 0:
                    for file in rule_stats[rule]["files"]:
                        r_file.write("{0};{1};{2};{3};{4};{5}\n".format(rule,
                                                            len(rule_stats[rule]["files"]),
                                                            file,
                                                            file_stats[file]["md5"],
                                                            file_stats[file]["sha1"],
                                                            file_stats[file]["sha256"]
                                                            ))
                # Rules without matches
                else:
                    r_file.write("{0};{1};{2};{3};{4};{5}\n".format(rule,len(rule_stats[rule]["files"]),"-","-","-","-"))

            except Exception,e:
                print "Error while formatting line - skipping it - CSV results may be incomplete"


def print_welcome():
    print "======================================================================="
    print "  "
    print "  yarAnalyzer"
    print "  "
    print "  (c) Florian Roth"
    print "  June 2015"
    print "  Version 0.3.3"
    print "  "
    print "======================================================================="
    print "  "


# MAIN ################################################################
if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='yarAnalyzer - Yara Rules Statistics and Analysis')
    parser.add_argument('-p', help='Path to scan', metavar='path', default='C:\\', required=True)
    parser.add_argument('-s', help='Path to signature file(s)', metavar='sigpath', default="{0}".format(os.path.join(get_application_path(), './signatures')))
    parser.add_argument('-e', help='signature extension', metavar='ext', default='yar')
    parser.add_argument('-i', help='Set an identifier - will be used in filename identifier_rule_stats.csv and identifier_file_stats.csv', metavar='identifier', default='yarAnalyzer')
    parser.add_argument('-m', help='Max file size in MB (default=10)', metavar='max-size', default=10)
    parser.add_argument('-l', help='Max filename/rulename string length in command line output', metavar='max-string', default=30)
    parser.add_argument('-f', help='Number of first bytes to show in output', metavar='first-bytes', default=6)
    parser.add_argument('--excel', action='store_true', default=False, help='Add extras to suppress automatic conversion in Microsoft Excel')
    parser.add_argument('--noempty', action='store_true', default=False, help='Don\'t show empty values')
    parser.add_argument('--printAll', action='store_true', help='Print all files that are scanned', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Print Welcome ---------------------------------------------------
    print_welcome()
    try:
        t_hostname = os.environ['COMPUTERNAME']
    except Exception, e:
        t_hostname = os.uname()[1]

    # Compile Yara Rules
    yara_rules = initialize_yara_rules(args.s, args.e)

    # Generate Stats Structure ----------------------------------------
    # Global vars that will be filled and read during report generation
    rule_stats = {}
    file_stats = {}
    generate_yara_stats_structure(yara_rules)

    # Scan Path -------------------------------------------------------
    scan_path(args.p, yara_rules, int(args.f))

    # Result ----------------------------------------------------------
    pretty_print(args.noempty, args.l)
    save_stats(args.noempty, args.i, args.excel)
