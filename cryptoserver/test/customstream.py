from project.crypto import *

import unittest

from project.util.timeout import timeout

class TestCustomStreamCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = project.crypto.stream(16983550252425474231928813359809892369676144841286610995871618350647041342051864240445596395744627506498762474229763678893377931321726550589297664292478932607125425931549303120912999983608102657696589053339572417143544483290273707770800083107455081725358378921639239561349319650616273512316440382647061058201773672319508474588943647995015652890819742505559157340776830934513821106083291302414235942221277798368674294209336838951777058062998751733603611836631965654174382192206676286509362910348576292382946435054830657597200319727086308360538564740526582355922138182576026209644159093667577634055978893434266165600823,18694068773207146779222189405765010822606143372880602908562931528572170983064486933206200358023915382382613846160047609483049750639485636617160615745088920113442889048441816955044797086214763458637006298976774021610418473829007322920843504587476451906185266238660775640806766708449742209277798571165647759876175019950573863223639657286559874604534093408057963936027623327147067784083002196763051884155827086636434043451085605666593418730575237552554914262141828263021511076749140792364886030828821346847382645180163103717412925431864394187458972055792095322521392943270910789936293449151215894215069321527107921680123)

    def test_shift_register_update(self):

        pass

    def test_stream_reset(self):

        pass

    def test_msb(self):

        pass

    def test_small_encipherment(self):
        pass

    def test_medium_encipherment(self):
        pass

    def test_complete_encipherment(self):
        pass

    def test_small_decipherment(self):

        pass

    def test_medium_decipherment(self):

        pass


    def test_complete_decipherment(self):

        pass

if __name__ == "__main__":
    unittest.main()