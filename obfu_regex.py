def obfu_regex(address, lines):
    noJunk = True



    # \tlea r11,\s+(qword ptr )?\[rsp+([0-9a-fA-F]+)h?\]\n(.*\tmov.*\n)\{-}.*\t(push r11\n.*\tpop rsp|mov rsp,\s+r11)\n([^ ]+)
    import re

    regex = r"\tlea r11,\s+(?:qword ptr )\[rsp\+([0-9a-fA-F]+)h?\]\n(?:.*\tmov.*\n)*?.*\t(?:push r11\n\.text:([^ ]+).*\tpop rsp)" 

    matches = re.finditer(regex, "\n".join(lines))

    if matches:
        #  Group 1 found at 15884-15886: 90 <-- stack adjustment required
        #  Group 2 found at 17191-17200: 1449180c6 <-- address to apply adjustment
        for matchNum, match in enumerate(matches, start=1):
            for groupNum in range(0, len(match.groups())):
                groupNum = groupNum + 1
                
                print(("Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum))))

                if groupNum == 2:
                    ea = NextHead(int(match.group(groupNum), 16))
                    newSpd = int(match.group(groupNum - 1), 16) + 8
                    print("newSpd", newSpd)
                    if GetSpDiff(ea) != newSpd:
                        SetSpDiff(ea, int(match.group(groupNum - 1), 16) + 8)
                        return 1
                    else:
                        print("Patch already applied")


    return 0

    r = [str(x) for x in lines]
    s = "\n".join(r)

    if noJunk:
        pattern = r'^(\s+jmp (loc_[0-9a-fA-F]+).*\n\2:)'
        s = re.sub(pattern, r';\U\1', s, 0, re.MULTILINE | re.IGNORECASE)

    pattern = r'^(\s+nop)'
    s = re.sub(pattern, r';\1', s, 0, re.MULTILINE | re.IGNORECASE)


    #  re_labeluse = r'^.+(##LABEL##)'  

    labelSet = set()
    #  labelUsed = set()
    # re_labels = r'^(\w[a-zA-Z0-9_:]+):'
    re_labels = r'^(\w+):' # [a-zA-Z0-9_:]+):'
    matches = re.finditer(re_labels, s, re.MULTILINE)
    for matchNum, match in enumerate(matches, start=1):
        labelSet.add(match.group(1))

    if debug: sprint("labelSet: %s" % labelSet)

    for label in labelSet:
        loc = idc.get_name_ea_simple(label)
        if loc == BADADDR:
            loc = idc.get_name_ea_simple(label.replace('__', '::', 1))
            if loc == BADADDR:
                print("0x%x: Can't find label %s" % (slowtrace2.startFnStart, label))
                raise RelocationAssemblerError()
        s = re.sub("0x%x" % loc, label, s, 0, re.IGNORECASE)
        #  sprint("labeluse_pattern: %s" % re_labeluse.replace('##LABEL##', label))
        #  if len(re.findall(re_labeluse.replace('##LABEL##', label), s, re.MULTILINE)):
            #  labelUsed.add(label)

    #  sprint("labelUsed: %s" % labelUsed)
    #  labelUnused = labelSet - labelUsed
    #  sprint("labelUnused: %s" % labelUnused)

    #  re_labeldef = r'^##LABEL##:'
    #  for label in labelUnused:
        #  s = re.sub(re_labeldef.replace('##LABEL##', label), '', s, 0, re.MULTILINE)

    s = re.sub(r';.*',  '', s, 0, re.MULTILINE)
    s = re.sub(r'\s+$', '', s, 0, re.MULTILINE)
    s = re.sub(r'^$\n', '', s, 0, re.MULTILINE)

    #  sprint("Labels: %s" % labelUsed)

    print("---[b4good]---")
    print(s)

    good = ""

    pattern = r'^((?:\w+:\n)+)((?:\t.*\n)*)'
    matches = re.finditer(pattern, s + "\n", re.MULTILINE)
    labelParse = set()
    for matchNum, match in enumerate(matches, start=1):
        labels = [x.strip(':') for x in match.group(1).splitlines()]
        seen = False
        lastLabel = ""
        for label in labels:
            lastLabel = label
            if label in labelParse:
                seen = True
            else:
                labelParse.add(label)
                good += label + ":\n"

        if not seen:
            good += s[match.start(2):match.end(2)]
        else:
            good += "\tjmp " + lastLabel + "\n"

    s = good + "\n"
    print("---[aftergood]---")
    print(s)
    print("---[end]---")

    if True:
        regex = r"^\s+jmp (\w+)\n\1:"
        s = re.sub(regex, r'\1:', s, 0, re.MULTILINE | re.IGNORECASE)


