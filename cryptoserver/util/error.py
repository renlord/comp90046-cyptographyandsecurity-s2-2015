class InvalidDHComputation(Exception):
    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual

    def errorMessage(self):
        return "Client DH Computation Error. Expected: " + str(self.expected) + "| Actual: " + str(self.actual)

class NonMatchingDHSharedKey(Exception):
	def __init__(self, expected, actual):
		self.expected = expected
		self.actual = actual

	def errorMessage(self):
		return "Client DH Shared Key does not match Server DH Shared Key.\n" + "Expected: " + str(self.expected) + "\n" + "Actual: " + str(self.actual) 