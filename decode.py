# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# Blackpoint Cyber APG modified main function to decode malware
# Added the following functions for decoding:
# or_key_finder, Decode, print_results
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Union, Optional

if TYPE_CHECKING:
    from dnfile import dnPE
    from dnfile.mdtable import MethodDefRow

import re
import argparse
import sys
import dnfile
from dnfile.enums import MetadataTables

from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

# key token indexes to dotnet meta tables
DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe: dnPE, row: MethodDefRow):
        """ """
        self.pe: dnPE = pe
        self.offset: int = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        """ """
        data: bytes = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        """ """
        return self.offset

    def seek(self, offset: int) -> int:
        """ """
        self.offset = offset
        return self.offset


def read_dotnet_user_string(pe: dnfile.dnPE, token: StringToken) -> Union[str, InvalidToken]:
    """read user string from #US stream"""
    try:
        user_string: Optional[dnfile.stream.UserString] = pe.net.user_strings.get_us(token.rid)
    except UnicodeDecodeError as e:
        return InvalidToken(token.value)

    if user_string is None:
        return InvalidToken(token.value)

    return user_string.value


def resolve_token(pe: dnPE, token: Token) -> Any:
    """ """
    if isinstance(token, StringToken):
        return read_dotnet_user_string(pe, token)

    table_name: str = DOTNET_META_TABLES_BY_INDEX.get(token.table, "")
    if not table_name:
        # table_index is not valid
        return InvalidToken(token.value)

    table: Any = getattr(pe.net.mdtables, table_name, None)
    if table is None:
        # table index is valid but table is not present
        return InvalidToken(token.value)

    try:
        return table.rows[token.rid - 1]
    except IndexError:
        # table index is valid but row index is not valid
        return InvalidToken(token.value)


def read_method_body(pe: dnPE, row: MethodDefRow) -> CilMethodBody:
    """ """
    return CilMethodBody(DnfileMethodBodyReader(pe, row))


def format_operand(pe: dnPE, operand: Any) -> str:
    """ """
    if isinstance(operand, Token):
        operand = resolve_token(pe, operand)

    if isinstance(operand, str):
        return f'"{operand}"'
    elif isinstance(operand, int):
        return hex(operand)
    elif isinstance(operand, list):
        return f"[{', '.join(['({:04X})'.format(x) for x in operand])}]"
    elif isinstance(operand, dnfile.mdtable.MemberRefRow):
        if isinstance(operand.Class.row, (dnfile.mdtable.TypeRefRow,)):
            return f"{str(operand.Class.row.TypeNamespace)}.{operand.Class.row.TypeName}::{operand.Name}"
    elif isinstance(operand, dnfile.mdtable.TypeRefRow):
        return f"{str(operand.TypeNamespace)}.{operand.TypeName}"
    elif isinstance(operand, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow)):
        return f"{operand.Name}"
    elif operand is None:
        return ""

    return str(operand)


# Extracts the OR key used to encode strings
def or_key_finder(pe):

    for r in pe.net.resources:
        #convert byte data to hex
        hex_str = r.data.hex()
        hex_list = []
        
        #split hex string
        for i in hex_str:
            hex_list.append(i)


        #combine individual hex to double digits
        final_hex = []
        hex_list_length = len(hex_list)
        for val in range(0, hex_list_length, 2):
            final_hex.append(hex_list[val] + hex_list[val+1])
        
        #convert hex values to binary or_key
        or_key = []
        for entry in final_hex:
            or_key.append(int(entry, 16))
            
        return or_key
        

# Decoder function to reverse strings encoded with OR key
def Decode(somestring, somenumber, or_key):
    num = len(somestring)
    array = list(somestring)
    num -= 1

    while num >= 0:
        array[num] = chr(ord(array[num]) ^ ((or_key[somenumber & 240 >> 4]) | somenumber))
        num -= 1
    decrypted_str = ''.join(array)
    
    return decrypted_str


# Prints and formats output
def print_results(decrypted_results):
    key_regex = re.compile('(\d{6}-){7}\d{6}')
    possible_key = ''
    possible_password = ''
    
    for i in range(0, len(decrypted_results)):
        if key_regex.match(decrypted_results[i]):
            possible_key = decrypted_results[i]
            possible_password = decrypted_results[i-1]
        print('Text = ' + decrypted_results[i] + '\n')
    
    if len(possible_key) > 0 and len(possible_password) > 0:
        print('\n\nPossible BitLocker Recovery Key: ' + possible_key)
        print('\nPossible BitLocker Password: ' + possible_password + '\n\n')


def main(args):
    """ """
    pe: dnPE = dnfile.dnPE(args.path)
    
    or_key = or_key_finder(pe)
    
    decrypted_results = []

    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            # skip methods that do not have a method body
            continue

        try:
            body: CilMethodBody = read_method_body(pe, row)
        except MethodBodyFormatError as e:
            print(e)
            continue

        if not body.instructions:
            continue

        hit = False
        encrypted_data = ''
        key = 0
        solve = 0
        
        # Extracts parameters from fuction calls
        for insn in body.instructions:
            param = format_operand(pe, insn.operand)
            
            if 'None' not in param:
                if hit == True:
                    hit = False
                    try:
                        key = int(param, 16)
                        solve += 1
                    except:
                        "Error in key"
                # identifies parameters for calling the encoding function        
                if '"' in param:
                    if len(param) > 2:
                        hit = True
                        encrypted_data = str(param).strip('\"')
                        solve += 1
            # Sends identified parameter and following parameter to decoder function
            if solve == 2:
                decrypted_results.append(Decode(encrypted_data, key, or_key))
                solve = 0
                
    print_results(decrypted_results)
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Extract and Decode IL from the managed methods of a Lorenz .NET binary")
    parser.add_argument("path", type=str, help="Full path to .NET binary")

    main(parser.parse_args())