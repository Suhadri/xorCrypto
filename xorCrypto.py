#!/usr/bin/python
# Author: Suhadri Shekar Paul (email: suhadri.s.paul@gmail.com)
# Revised on:
# Description: 
#
#
#
import base64, os
import ConfigParser
import StringIO

class cryptoLib():
    def __init__(self):
        self.__l = 3

    def __find_len(self, x):
        t = x
        c = 0
        tup = []
        a = tuple(str(x))
        while True:
            if not t < 10:
                a = divmod(t, 10)
                t = a[0]
                tup.insert(0, a[1])
                c = c + 1
            else:
                tup.insert(0, int(a[0]))
                break
        while len(tup) < self.__l:
            tup.insert(0, 0)
        return len(tup), tuple(tup)

    def get_ascii_list(self, pasw_comb):
        abc = []
        # print pasw_comb.split()
        for i in zip(pasw_comb):
            val = self.__find_len(ord("".join(i)))[1]
            # print map(str, val)
            abc.append(''.join(map(str, val)))
        return abc


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class WrongKeyError(Error):
    """Exception raised for Wrong Key provided for the passwords file.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message


class Cryptoxor(object):
    def __init__(self, key, filename=None):
        """
        :param key: Encrytion Key
        :param filename: Optional value. Full file path has to be provided
        """
        self.__enc_obj = cryptoLib()
        if filename:
            # print "yes I am here"
            self.__fileloc = filename
        else:
            self.__fileloc = None
        self.__key = key
        # self.__key = self.__test_set_crypt_key(key)

    def encrypt(self, e_val ):
        # print "eeeeeeeeeeeeeeee",e_val
        ascii_list_comb = self.__enc_obj.get_ascii_list(e_val)
        # print "eeeeeeeeeeeeeeee",ascii_list_comb
        ascii_list_key = self.__enc_obj.get_ascii_list(self.__key)
        int_asc_key = int("1" + ''.join(ascii_list_key))
        int_asc_nums = int("1" + ''.join(ascii_list_comb))
        encrypted_val = (int_asc_nums ^ int_asc_key)
        return encrypted_val

    def decrypt(self, e_val):
        dec_ascii_list_key = self.__enc_obj.get_ascii_list(self.__key)
        dec_k = int("1" + ''.join(dec_ascii_list_key))  ## decryption key
        # print dec_k, type(dec_k), e_val
        # print dec_k
        dec_v = (dec_k ^ int(e_val))  # xor decrypted value
        act_dec_ascii_list = ''.join((char for idx, char in enumerate(str(dec_v)) if idx not in [0]))
        # print act_dec_ascii_list
        n = 3
        nums_list = [act_dec_ascii_list[i:i + n] for i in range(0, len(act_dec_ascii_list), n)]
        decrypted_value = []
        # print "this is it", nums_list
        for i in nums_list:
            decrypted_value.append(chr(int(i)))
        return ''.join(decrypted_value)

    # Key Setter. will validate if the key provided is correct.
    # Not implemented yet. Has to be reviewed in upcoming versions.
    def __test_set_crypt_key(self, key):
        if self.__fileloc:
            # print "I reached here now"
            # using this type of file handling to support all python2.x.x versions
            key_from_file = open(self.__fileloc, 'rb').readline().rstrip()
            # print key_from_file
            self.__key = key
            dec_key_frm_file = self.decrypt(key_from_file)
            # print "+++++++",dec_key_frm_file
            if not dec_key_frm_file == base64.b16decode(base64.b64decode(
                    "NzQ2NTczNzQ1RjZCNjU3OTNENzM3NTY4NjE2NDcyNjkyRTcwNjE3NTZDNDA2RjcyNjE2MzZDNjUyRTYzNkY2RA==")):
                raise WrongKeyError("Wrong Key provided.")
        else:
            self.__key = key

    def __get_values_from_file(self):
        if self.__fileloc:
            conf = StringIO.StringIO()
            conf.write('[dummy_section]\n')
            file_details = open(self.__fileloc, 'rb').readlines()
            # conf.write(file_details.read().replace('%', '%%'))
            # print file_details
            # print type(file_details)
            for line in file_details:
                # print self.decrypt(line)
                # print "_get_values_result 0",line
                # print "_get_values_result 1 ",self.decrypt(line)
                conf.write(self.decrypt(line)+'\n')
            conf.seek(0, os.SEEK_SET)

            cp = ConfigParser.SafeConfigParser()
            cp.optionxform = str
            cp.readfp(conf)

            # print "_get_values_result 2 ",cp

            return dict(cp.items('dummy_section'))
        else:
            raise WrongKeyError("No Files to update")

    def get_values_from_file(self):
        return self.__get_values_from_file()

    def add_password_to_file(self, user, password):
        pass_dict = self.__get_values_from_file()
        # print "++++++++++++ 0000  ", pass_dict
        pass_dict[user] = password
        # print "++++++++++++ 1  ",pass_dict
        enc_file_content = []
        for u_raw,p_raw in pass_dict.items():
            # print "++++++++++++ 2  ",u_raw,p_raw
            enc_file_content.append(self.encrypt(str(u_raw)+"="+str(p_raw)))
        # print "++++++++++++ 3  ",enc_file_content
        try:
            f = open(self.__fileloc,'wb')
            for enc_line in enc_file_content:
                f.writelines(str(enc_line)+'\n')
        except Exception, E:
            print E.__str__()
        finally:
            f.close()


print "----------------------------------------------------------------------------------------------------------------------------"
# filename = "enc_passes.txt"
# x = Cryptoxor("T@estXor1", filename=filename)
# print x
######Tested this section # enc = x.encrypt("test_appid=N0@pp#D")
######Tested this section # print enc
######Tested this section # act_txt = x.decrypt(enc)
######Tested this section # print act_txt
# This section is tested #
# print x.get_values_from_file()
# x.add_password_to_file("test_key", "suhadri.paul@oracle.com")
# x.add_password_to_file("DB_ADMIN_PWD", "SYSPassword")
# print x.get_values_from_file()
