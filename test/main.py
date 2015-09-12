import unittest

from test.des import TestDESMethods
from test.dhex import TestDHEXMethods
from test.stream import TestStreamMethods
from test.supplementary import TestSupplementaryMethods

if __name__ == "__main__":
	suite = unittest.TestSuite()
	for method in dir(TestDHEXMethods):
		if method.startswith("test"):
			suite.addTest(TestDHEXMethods(method))
	for method in dir(TestSupplementaryMethods):
		if method.startswith("test"):
			suite.addTest(TestSupplementaryMethods(method))
	for method in dir(TestStreamMethods):
		if method.startswith("test"):
			suite.addTest(TestStreamMethods(method))
	for method in dir(TestDESMethods):
		if method.startswith("test"):
			suite.addTest(TestDESMethods(method))
	unittest.TextTestRunner().run(suite)
