import sys
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect.Config.ResourceType import ResourceType

from examples.working_init import *
tc.set_tcl_file('log/tc.log', 'critical')
tc.set_tcl_console_level('debug')

indics = tc.indicators()

def get_vt(hash):
    return 'blah'

try:
    filter1 = indics.add_filter(IndicatorType.FILES)
except AttributeError as e:
    print(e)
    pass

try:
    indics.retrieve()
except RuntimeError as e:
    print(e)
    sys.exit(1)

for i in indics:
    print(i.indicator['md5'])
    print(i.indicator['sha1'])
    print(i.indicator['sha256'])

    if i.indicator["md5"] is None or i.indicator["sha1"] is None or i.indicator["sha256"] is None:

        ind = i.indicator
        vt = None
        commit = False

        try:
            if ind["md5"] is None:
                # vt = get_vt(ind["md5"])
                i.set_indicator('C472F1181CB9852AB1BBD5FFF6845B47')
                commit = True
            if ind["sha1"] is None:
                # vt = get_vt(ind["sha1"])
                i.set_indicator('11B7ECC5FAF7456A450267F3BBF2D2B8DE6DEEEE')
                commit = True
            if ind["sha256"] is None:
                # vt = get_vt(ind["sha256"])
                i.set_indicator('727C1EF3D72FE938A5E1DB58DC9BAD7EEFD8FACD70B9E8B60EB9DD123A35EEEE')
                commit = True

            # if vt is not None:
            #     if ind["md5"] is None:
            #         i.set_indicator(str(vt.md5), ResourceType.FILES)
            #     if ind["sha1"] is None:
            #         i.set_indicator(str(vt.sha1), ResourceType.FILES)
            #     if ind["sha256"] is None:
            #         i.set_indicator(str(vt.sha256), ResourceType.FILES)

            #     print "Update hashes"
            #     print "MD5: " + vt.md5
            #     print "SHA1: " + vt.sha1
            #     print "SHA256: " + vt.sha256

            if commit:
                print('committing')
                ii = i.commit()
                print str(ii)
        except Exception, e:
            print "ERROR: " + str(e)
