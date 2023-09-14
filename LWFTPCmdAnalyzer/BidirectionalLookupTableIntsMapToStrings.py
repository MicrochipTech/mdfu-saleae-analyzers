


class BidirectionalLookupTableIntsMapToStrings():
    '''A class for prividing a bidirectional lookup'''

    def __init__(self, bidirectionalLookupTableName, keyValueDictionary):
        self.bidirectionalLookupTableName = bidirectionalLookupTableName
        self.dictionary = keyValueDictionary

        self.CheckForUniqueValues()
        self.CheckForUniqueStrings()


    def GetValue(self, string): 
        valueFound = False
        for key, value in self.dictionary.items():
            if value == string:
                intToReturn = key 
                valueFound = True
                break

        if not valueFound:
            raise ValueError('Entry - "' + string + '"' + " is not present in bidirectional lookup table named: " + self.bidirectionalLookupTableName)
            
        return intToReturn 
 
    def GetString(self, intValue):
        lookupString = self.dictionary.get(intValue, "BDLT Item Not Found!")

        if lookupString == "BDLT Item Not Found!":
            raise ValueError("Entry - " + str(intValue) + " is not present in bidirectional lookup table named: " + self.bidirectionalLookupTableName)
        
        return lookupString

    def IsValidValue(self, intValue):
        lookupString = self.dictionary.get(intValue, "BDLT Item Not Found!")
        if lookupString == "BDLT Item Not Found!":
            return False
        else:
            return True
        

    def CheckForUniqueValues(self):  
        if (len(self.dictionary) != len(set(self.dictionary.keys()))):
            raise ValueError("Dictionary passed to Bidirectional Lookup Table Ints Map to Strings contains duplicate ints in: " + self.bidirectionalLookupTableName)
 
    def CheckForUniqueStrings(self): 
        if (len(self.dictionary) != len(set(self.dictionary.values()))):
            raise ValueError("Dictionary passed to BidirectionalLookupTableIntsMapToStrings contains duplicate strings in: " + self.bidirectionalLookupTableName)

    



