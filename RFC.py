import re
import numpy as np
import time
import bisect
import math, sys


class Rule:
    def __init__(self, ranges):
        # each range is left inclusive and right exclusive, i.e., [left, right)
        #self.priority = priority
        self.ranges = ranges
        self.names = ["src_ip0", "src_ip1", "dst_ip0", "dst_ip1", "src_port", "dst_port", "proto"]

class Phase0:
    def __init__(self, RFCTable, Bitmap, mapping, CESnum, RFCPoint):
        self.RFCTable = RFCTable
        self.Bitmap = Bitmap
        #eqID到位图的映射
        self.MAP = mapping
        self.CESnum = CESnum
        self.RFCPoint = RFCPoint

def phase0_lookup(phase0, field_index, value):
    points = phase0.RFCPoint[field_index]
    j = bisect.bisect_right(points, value) - 1
    if j < 0:
        return None
    return phase0.RFCTable[field_index][j]

class Phase1:
    def __init__(self, RFCTable, Bitmap, mapping, CESnum):
        self.RFCTable = RFCTable
        self.Bitmap = Bitmap
        #eqID到位图的映射
        self.MAP = mapping
        self.CESnum = CESnum

class Phase2:
    def __init__(self, RFCTable):
        self.RFCTable = RFCTable

def loadRulesfromFile(filename):
    rules = []
    rule_fmt = re.compile(r'(\d+).(\d+).(\d+).(\d+)/(\d+) ' \
                          r'(\d+).(\d+).(\d+).(\d+)/(\d+) ' \
                          r'(\d+) : (\d+) ' \
                          r'(\d+) : (\d+) ' \
                          r'(0x[\da-fA-F]+)/(0x[\da-fA-F]+) ' \
                          r'(.*?)')
    for idx, line in enumerate(open(filename)):
        elements = line[1:-1].split('\t')
        line = line.replace('\t', ' ')

        # re.match尝试从字符串的起始位置匹配一个模式，如果不是起始位置匹配成功的话，match()就返回 None
        sip0, sip1, sip2, sip3, sip_mask_len, \
            dip0, dip1, dip2, dip3, dip_mask_len, \
            sport_begin, sport_end, \
            dport_begin, dport_end, \
            proto, proto_mask = \
            (eval(rule_fmt.match(line).group(i)) for i in range(1, 17))

        sip0 = (sip0 << 24) | (sip1 << 16) | (sip2 << 8) | sip3
        sip_begin = sip0 & (~((1 << (32 - sip_mask_len)) - 1))
        sip_begin1 = sip_begin >> 16
        sip_begin2 = sip_begin & 0xFFFF
        # 结束：主机位全1
        sip_end = sip0 | ((1 << (32 - sip_mask_len)) - 1)
        sip_end1 = sip_end >> 16
        sip_end2 = sip_end & 0xFFFF

        dip0 = (dip0 << 24) | (dip1 << 16) | (dip2 << 8) | dip3
        dip_begin = dip0 & (~((1 << (32 - dip_mask_len)) - 1))
        dip_begin1 = dip_begin >> 16
        dip_begin2 = dip_begin & 0xFFFF
        dip_end = dip0 | ((1 << (32 - dip_mask_len)) - 1)
        dip_end1 = dip_end >> 16
        dip_end2 = dip_end & 0xFFFF

        if proto_mask == 0xff:
            proto_begin = proto
            proto_end = proto
        else:  # 协议未指定
            proto_begin = 0
            proto_end = 0xff

        rules.append(
            Rule([
                sip_begin1, sip_end1 + 1, sip_begin2, sip_end2 + 1,
                dip_begin1, dip_end1 + 1, dip_begin2, dip_end2 + 1, sport_begin,
                           sport_end + 1, dport_begin, dport_end + 1, proto_begin,
                           proto_end + 1
            ]))
    return rules


def CreatePhase0(rules):
    RFCTable = []
    RFCPoint = []
    rulenum = len(rules)
    rangelen = [16, 16, 16, 16, 16, 16, 8]
    Bitmap = []
    Map = []
    CESnum = []
    for i in range(7):
        #rangeset = set()
        point = set()
        for rule in rules:
            #rangeset.add((rule.ranges[i * 2], rule.ranges[i * 2 + 1]))
            point.add(rule.ranges[i * 2])
            point.add(rule.ranges[i * 2 + 1])
        eqID = 0
        #bitmap0 = BitVector(size=rulenum)
        bitmap = 0
        point.add(0)

        length = np.power(2, rangelen[i])
        point.add(length)
        mapping = { eqID: bitmap }
        mapping1 = { bitmap: eqID }
        l = len(point)
        #创建查找表
        table = []
        bitmapset = set()
        bitmapset.add(bitmap)
        list = sorted(point)
        RFCPoint.append(list)
        #采用一种不建全表的方式
        for j in range(l - 1):
            point1 = list[j]
            #point2 = list[j + 1]
            bitmap = 0
            for k in range(rulenum):
                pos = rulenum - k - 1
                if rules[k].ranges[i * 2] <= point1  < rules[k].ranges[i * 2 + 1]:
                    bitmap = bitmap + (1 << pos)
            if bitmap in bitmapset:
                #table[j] = mapping1.get(l)
                table.append(mapping1.get(bitmap))
            else:
                eqID = eqID + 1
                table.append(eqID)
                mapping[eqID] = bitmap
                mapping1[bitmap] = eqID
                bitmapset.add(bitmap)

        print(f"Phase 0: the number of CES in field {i} is {bitmapset.__len__()}, the length of RFCTable is {len(table)}")
        RFCTable.append(table)
        Bitmap.append(bitmapset)
        Map.append(mapping)
        CESnum.append(eqID + 1)

    phase0 = Phase0(RFCTable, Bitmap, Map, CESnum, RFCPoint)
    return phase0


def CreatePhase1(phase0, rulenum):
    list = []
    RFCTable = []
    Bitmap = []
    Map = []
    CESnum = []
    #0-1 2-3 4-5-6
    for i in range(3):
        dims = []
        if i == 0:
            dims =[0, 1]
        elif i == 1:
            dims =[2, 3]
        else:
            dims =[4, 5, 6]
        #RFC查找表
        eqID = 0
        #bitmap0 = BitVector(size=rulenum)
        bitmap = 0
        mapping = {eqID: bitmap}
        mapping1 = {bitmap: eqID}
        table = dict()
        bitmapset = set()
        if len(dims) == 2:
            for c0 in range(phase0.CESnum[dims[0]]):
                bmp0 = phase0.MAP[dims[0]][c0]
                if bmp0 == 0:
                    continue
                for c1 in range(phase0.CESnum[dims[1]]):
                    bmp1 = phase0.MAP[dims[1]][c1]
                    if bmp1 == 0:
                        continue
                    newbmp = bmp0 & bmp1
                    if newbmp != 0:
                        idx = c0 * phase0.CESnum[dims[1]] + c1
                        if newbmp not in bitmapset:
                            bitmapset.add(newbmp)
                            eqID = eqID + 1
                            mapping[eqID] = newbmp
                            mapping1[newbmp] = eqID
                            table[idx] = eqID
                        else:
                            table[idx] = mapping1[newbmp]


        elif len(dims) == 3:
            for c0 in range(phase0.CESnum[dims[0]]):
                bmp0 = phase0.MAP[dims[0]][c0]
                if bmp0 == 0:
                    continue
                for c1 in range(phase0.CESnum[dims[1]]):
                    bmp1 = phase0.MAP[dims[1]][c1]
                    if bmp1 == 0:
                        continue
                    tmp = bmp0 & bmp1
                    if tmp == 0:
                        continue
                    for c2 in range(phase0.CESnum[dims[2]]):
                        bmp2 = phase0.MAP[dims[2]][c2]
                        newbmp = tmp & bmp2
                        if newbmp != 0:
                            idx = c0 * phase0.CESnum[dims[1]] * phase0.CESnum[dims[2]] + c1 * phase0.CESnum[dims[2]] + c2
                            if newbmp not in bitmapset:
                                bitmapset.add(newbmp)
                                eqID = eqID + 1
                                mapping[eqID] = newbmp
                                mapping1[newbmp] = eqID
                                table[idx] = eqID
                            else:
                                table[idx] = mapping1[newbmp]
        print(f"Phase 1: the number of CES in field {i} is {bitmapset.__len__()}, the length of RFCTable is {len(table)}")
        RFCTable.append(table)
        Bitmap.append(bitmapset)
        Map.append(mapping)
        CESnum.append(eqID + 1)

    phase1 = Phase1(RFCTable, Bitmap, Map, CESnum)
    return phase1



def CreatePhase2(phase1, rulenum):
    #bitmap0 = BitVector(size=rulenum)
    bitmap = 0
    table = dict()
    for c0 in range(phase1.CESnum[0]):
        bmp0 = phase1.MAP[0][c0]
        if bmp0 == 0:
            continue
        for c1 in range(phase1.CESnum[1]):
            bmp1 = phase1.MAP[1][c1]
            if bmp1 == 0:
                continue
            tmp = bmp0 & bmp1
            if tmp == 0:
                continue
            for c2 in range(phase1.CESnum[2]):
                bmp2 = phase1.MAP[2][c2]
                newbmp = tmp & bmp2
                if newbmp != 0:
                    idx = c0 * phase1.CESnum[1] * phase1.CESnum[2] + c1 * phase1.CESnum[2] + c2
                    # t = (newbmp & -newbmp).bit_length() - 1
                    # pos = rulenum - t - 1
                    pos = rulenum - newbmp.bit_length()
                    table[idx] = pos
                    # for i in range(rulenum):
                    #     if newbmp[i] == 1:
                    #         table[idx] = i
                    #         break

    print('Phase 2: the number of CES in chunk 0 is ' + str(len(table)))

    phase2 = Phase2(table)
    return phase2


def test_lookup_from_file(filename, phase0, phase1, phase2):
    """
    filename: 测试文件，每行 7 个整数
    phase0 / phase1 / phase2: 已构建好的 RFC 阶段
    """

    hit = 0
    total = 0
    ind = 0
    with open(filename, "r") as f:
        starttime = time.time()
        for line in f:
            if not line.strip():
                continue

            fields = list(map(int, line.strip().split()))
            assert len(fields) == 7

            # ---------- Phase 0 ----------
            eq = [0] * 7
            eq[0] = phase0_lookup(phase0, 0, fields[0] // 65536)
            eq[1] = phase0_lookup(phase0, 1, fields[0] % 65536)
            eq[2] = phase0_lookup(phase0, 2, fields[1] // 65536)
            eq[3] = phase0_lookup(phase0, 3, fields[1] % 65536)
            eq[4] = phase0_lookup(phase0, 4, fields[2])
            eq[5] = phase0_lookup(phase0, 5, fields[3])
            eq[6] = phase0_lookup(phase0, 6, fields[4])

            # ---------- Phase 1 ----------
            # chunk 0: (0,1)
            idx0 = eq[0] * phase0.CESnum[1] + eq[1]
            c0 = phase1.RFCTable[0][idx0]

            # chunk 1: (2,3)
            idx1 = eq[2] * phase0.CESnum[3] + eq[3]
            c1 = phase1.RFCTable[1][idx1]

            # chunk 2: (4,5,6)
            idx2 = (
                eq[4] * phase0.CESnum[5] * phase0.CESnum[6]
                + eq[5] * phase0.CESnum[6]
                + eq[6]
            )
            c2 = phase1.RFCTable[2][idx2]

            # ---------- Phase 2 ----------
            final_idx = (
                c0 * phase1.CESnum[1] * phase1.CESnum[2]
                + c1 * phase1.CESnum[2]
                + c2
            )

            rule = phase2.RFCTable.get(final_idx, -1)
            #print(f"the rule matched for packet #{ind} is {rule}")
            if rule == fields[-1]:
                hit += 1

            total += 1
            ind += 1
        endtime = time.time()
        print(f"Lookup done: {hit}/{total} packets matched, total time: {endtime - starttime}s")


if __name__ == "__main__":
    rules = loadRulesfromFile("Filter_1K_acl4seed.txt")
    print(len(rules))
    starttime = time.time()
    starttime0 = time.time()
    phase0 = CreatePhase0(rules)
    endtime0 = time.time()
    print(f"the time spent for creating phase0 is {endtime0 - starttime0:.4f} s")
    starttime1 = time.time()
    phase1 = CreatePhase1(phase0, len(rules))
    endtime1 = time.time()
    print(f"the time spent for creating phase1 is {endtime1 - starttime1:.4f} s")
    starttime2 = time.time()
    phase2 = CreatePhase2(phase1, len(rules))
    endtime2 = time.time()
    print(f"the time spent for creating phase2 is {endtime2 - starttime2:.4f} s")
    endtime = time.time()
    print(f"the time spent for RFC preprocessing is {endtime - starttime:.4f} s")
    test_lookup_from_file("Filter_1K_acl4seed_trace.txt", phase0, phase1, phase2)
    print("Hello World")