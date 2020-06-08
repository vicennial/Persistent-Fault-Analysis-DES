#include <iostream>
#include <string>
#include <cmath>
#include <vector>
#include <algorithm>
using namespace std;

class DES{ //Class that contains all functions and data required to perform DES encryption

public:

string _key,_ct; // stores key and ciphertext in binary format
vector<string> _subKeys; // list of subkeys 

DES(string key) : _key(key) {} // Constructor initialises DES key using HEXADECIMA input


vector<int> PC1 = { //Initial permutation mapping for key generation
	57,49,41,33,25,17,9, 
	1,58,50,42,34,26,18, 
	10,2,59,51,43,35,27, 
	19,11,3,60,52,44,36,		 
	63,55,47,39,31,23,15, 
	7,62,54,46,38,30,22, 
	14,6,61,53,45,37,29, 
	21,13,5,28,20,12,4 
};

vector<int> PC2 = { //Permutation to condense 56 bit key to 48 bits in each key generation round
	14,17,11,24,1,5, 
	3,28,15,6,21,10, 
	23,19,12,4,26,8, 
	16,7,27,20,13,2, 
	41,52,31,37,47,55, 
	30,40,51,45,33,48, 
	44,49,39,56,34,53, 
	46,42,50,36,29,32 
}; 

vector<int> shiftOnceRounds = { // Key generation rounds where the left and right part of key is left shited by 1 element instead of 2.
	0,1,8,15
};


int initialPermutation[64] = { // Initial permutation table before the rounds begin
58,50,42,34,26,18,10,2, 
60,52,44,36,28,20,12,4, 
62,54,46,38,30,22,14,6, 
64,56,48,40,32,24,16,8, 
57,49,41,33,25,17,9,1, 
59,51,43,35,27,19,11,3, 
61,53,45,37,29,21,13,5, 
63,55,47,39,31,23,15,7 
}; 

int expansion[48] = { // Expansion table to expand the right side 32-bit input of each round into 48-bits
32,1,2,3,4,5,4,5, 
6,7,8,9,8,9,10,11, 
12,13,12,13,14,15,16,17, 
16,17,18,19,20,21,20,21, 
22,23,24,25,24,25,26,27, 
28,29,28,29,30,31,32,1 
}; 

int sBox[8][4][16]=  //All 8 substitution boxes
{{ 
    14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 
    15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 
}, 
{ 
    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 
    13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 
}, 
{ 
    10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 
    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 
    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 
}, 
{ 
    7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 
    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 
    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 
}, 
{ 
    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 
    14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 
    11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 
}, 
{ 
    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 
    10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 
}, 
{ 
    4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 
    13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 
}, 
{ 
    13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 
}};

int permutationTable[32] = { // Permutation table for the permutations step of the fiestal round
16,7,20,21,29,12,28,17, 
1,15,23,26,5,18,31,10, 
2,8,24,14,32,27,3,9,
19,13,30,6,22,11,4,25 
}; 

int inversePermutation[64]= {  // Inverse permutation table of the inital permutation table to generate the final ciphertext
40,8,48,16,56,24,64,32, 
39,7,47,15,55,23,63,31, 
38,6,46,14,54,22,62,30, 
37,5,45,13,53,21,61,29, 
36,4,44,12,52,20,60,28, 
35,3,43,11,51,19,59,27, 
34,2,42,10,50,18,58,26, 
33,1,41,9,49,17,57,25 
};

void shift_left(string& partialKey,int ct){ // Shifts a string left by specified amount (ct)
	rotate(partialKey.begin(),partialKey.begin()+ct,partialKey.end());
} 

bool shiftOnceCheck(int round){ // Check if key should be left shifted once or twice in current key round
	return find(shiftOnceRounds.begin(),shiftOnceRounds.end(),round)!=shiftOnceRounds.end();
}


string hexToBin(string hexNum) { // Simple function to convert a hexadecimal number to binary
	string binS;
    for(int i=0;i<hexNum.size();i++){ 
  
        switch (hexNum[i]) { 
        case '0': 
            binS += "0000"; 
            break; 
        case '1': 
            binS += "0001"; 
            break; 
        case '2': 
            binS += "0010"; 
            break; 
        case '3': 
            binS += "0011"; 
            break; 
        case '4': 
            binS += "0100"; 
            break; 
        case '5': 
            binS += "0101"; 
            break; 
        case '6': 
            binS += "0110"; 
            break; 
        case '7': 
            binS += "0111"; 
            break; 
        case '8': 
            binS += "1000"; 
            break; 
        case '9': 
            binS += "1001"; 
            break; 
        case 'A': 
        case 'a': 
            binS += "1010"; 
            break; 
        case 'B': 
        case 'b': 
            binS += "1011"; 
            break; 
        case 'C': 
        case 'c': 
            binS += "1100"; 
            break; 
        case 'D': 
        case 'd': 
            binS += "1101"; 
            break; 
        case 'E': 
        case 'e': 
            binS += "1110"; 
            break; 
        case 'F': 
        case 'f': 
            binS += "1111"; 
            break; 
        default: 
            cout << "\nInvalid hexadecimal digit "
                 << hexNum[i]; 
        } 
    } 
    return binS;
} 

string binToHex(string binNum) { // Simple function to convert binary string to hexadecimal string
	string hexS;
	int size=binNum.size();
	if(size%4!=0){
		cout<<"Invalid Binary String!!"<<endl; 
		return "";
	}

    for(int i=0;i<binNum.size();i+=4){ 
    	string section = binNum.substr(i,4);
    	int num = (section[0]-'0')*8 + (section[1]-'0')*4 + (section[2]-'0')*2 + (section[3]-'0');
    	hexS += num<=9? '0'+num : 'a'+(num-10);
    } 
    return hexS;
} 

string decToBin(int decimal) {// Simple function to convert decimal integer to binary string
	string binary;
    while(decimal != 0) {
		binary = (decimal%2== 0 ? "0" : "1") + binary; 
		decimal = decimal/2;
	}
	while(binary.length() < 4){ //padding to make sure string size is always length 4.
		binary = "0" + binary;
	}
    return binary;
}


int binToDec(string binary){// Simple function to convert binary string to decimal integer
    int val = 0, powCt = 0, size = binary.length();
	for(int i = size-1; i >= 0; i--){
		val += binary[i]=='1'? 1<<powCt:0;
   	 	powCt++;
	}
	return val;
}


string stringXor(string a, string b){ //Calculates the xor string of two input strings
	string res; 
	int size = a.size();
	for(int i = 0; i < size; i++){ 
		res += a[i]!=b[i]?"1":"0";
	} 
	return res; 
} 



vector<string> generate_keys(string key){ // Generates a list of subkeys for all 16 rounds
    vector<string> subKeys;
    const int rounds = 16;
    string permutedKey; 
    for(int i = 0; i<56; i++){ // Initial permutation
        permutedKey+= key[PC1[i]-1]; 
    } 

    string left=permutedKey.substr(0,28); 
    string right=permutedKey.substr(28); 

    for(int i=0; i<rounds; i++){ 

        if(shiftOnceCheck(i)){ // Determine left shift amount
            shift_left(left,1); 
            shift_left(right,1);
        } 
        else{
            shift_left(left,2); 
            shift_left(right,2);
        }

    string mergedKey = left+right;
    string roundKey;

    for(int i = 0; i<48; i++){ 
        roundKey += mergedKey[PC2[i]-1]; // Second permutation
    }   
    subKeys.push_back(roundKey); // Store round keys
    } 
    return subKeys;
}

string goDES(string pt, vector<string> subKeys){ // Performs DES encryption on specified plaintext provided with subkeys generated by the key generation service


  	string perm; 
	for(int i = 0; i < 64; i++){ 
		perm += pt[initialPermutation[i]-1]; // Initial permutation
	}  

	string left = perm.substr(0, 32); // Split 64-bit block into two 32-bit blocks
	string right = perm.substr(32);

	for(int i=0; i<16; i++) { //Feistel round function
    	string rightExpansion; 

    	for(int i = 0; i < 48; i++) { // Expansion step
      		rightExpansion += right[expansion[i]-1]; 
    	};  

		string keyMixed = stringXor(subKeys[i], rightExpansion);  //Key mixing step
		string substitutionResult; 

		for(int i=0;i<8; i++){ // Substition with each S-Box by breaking into 6-bit length segments

			int startIndex = i*6;
      		string rowBinary= keyMixed.substr(startIndex,1) + keyMixed.substr(startIndex + 5,1);
      		int row = binToDec(rowBinary);

      		string colBinary = keyMixed.substr(startIndex + 1, 4);
			int col = binToDec(colBinary);

			int val = sBox[i][row][col];
			substitutionResult += decToBin(val);   // generated string after substitution is 4-bit
		} 

		string permStep; 
		for(int i = 0; i < 32; i++){ // Permutation step
			permStep += substitutionResult[permutationTable[i]-1]; 
		}

		keyMixed = stringXor(permStep, left); // Mix with left segment

		left = keyMixed; 
		if(i < 15){ // Swapping is done only in first 15 rounds
			swap(right,left);
		} 
	} 

	string combinedSegments = left + right;   // merge L16 and R16
	string ciphertext; 
	for(int i = 0; i < 64; i++){ // Inverse permutation step
		ciphertext+= combinedSegments[inversePermutation[i]-1]; 
	}

	return ciphertext; 
}



string calc(string pt){ // Function that can be called by user to encrypt a specified plaintext with internal key
    // Input plaintext is HEXADECIMAL format
    string key= _key;

    //convert plaintext and key from hexadecimal to binary for further processing
    string ptBin= hexToBin(pt);
    string keyBin= hexToBin(key); 

    //generate keys
    vector<string> subKeys = generate_keys(keyBin); 
    _subKeys = subKeys;

    //obtain ciphertext in binary format
    string binCt= goDES(ptBin, subKeys); 
    _ct = binCt;

    //convert binary ciphertext to hexadecimal
    string ct = binToHex(binCt);
    return ct;
}

void setFault(int val,int i,int j,int k){ // Used to introduce a fault in i'th S-box by replacing value at [j][k] location with 'val'
    sBox[i][j][k] = val;
}

};
