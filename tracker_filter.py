# This is very optimistic. Won't work if the string is wrongly formatted
def bdecode(string):
    stack = []
    while (len(string)  > 0):
        if (string[0] == "d"):
            stack.append({})
            string = string[1:]
        elif (string[0] == "l"):
            stack.append([])
            string = string[1:]
        elif (string[0] == "i"):
            splitted = string[1:].split('e', 1)
            stack.append(int(splitted[0]))
            string = splitted[1]
        elif (string[0] == "e"):
            item = stack.pop()
            items = []
            while (len(stack) > 0 and item != {} and item != []):
                items.append(item)
                item = stack.pop()
            items.reverse()
            if (len(items) == 0):
                raise ValueError('empty list or dictionary')
            if (item == []):
                stack.append(items)
            elif (item == {}):
                dic = {}
                if (len(items) % 2 == 1):
                    raise ValueError('odd number of key/values in dictionary')
                while (len(items) != 0):
                    dic[items[0]] = items[1]
                    items = items[2:]
                stack.append(dic)
            string = string[1:]
                
        else:
            splitted = string.split(':', 1)
            str_len = int(splitted[0])
            string = splitted[1]
            stack.append(string[:str_len])
            string = string[str_len:]
        
    return stack[0]

# Receives a packet and returns a boolean (true if it a packet matching the tracker protocol) and output (dictionary sent in the packet)
def tracker_filter(packet):
    data = str(packet.data)
    if (len(data) == 0 or data[0] not in ('d', 'l', 's')):
        return False, {}
    try:
        output = bdecode(data)
        return True, output
    except:
        return False, {}


def print_output(out, port="PORT"):
    try:
        if ('y' not in out.keys()):
            return 'Unable to parse output: no y key found.'
        y_str = 'Unknown'
        transaction = ''
        action = ''
        result = ' transaction=%s' % out['t'].encode('hex')
        y = out['y']
        if y == "q":
            y_str = "Query"
            action = out[y]
        elif y == "r":
            y_str = "Response"

        elif y == "e":
            y_str = "Error"
            result = out[y][1]

        if action == "announce_peer":
            if (out['a']['implied_port'] == 1):
                result+=" port=%s" % port
            else:
                result+=" port=%s" % out['a']['port']

        if action == "announce_peer" or action =="get_peers":
            hash = out['a']['info_hash']
            result+=" info_hash=%s" % hash.encode('hex')
        return "%s %s%s" % (y_str, action, result)
    except:
        return out

