#include <random>
#include "classDES.hpp"

vector<int> initialPermutation = { // Permutation table to convert the output of DES into the output of Round 16
58,50,42,34,26,18,10,2, 
60,52,44,36,28,20,12,4, 
62,54,46,38,30,22,14,6, 
64,56,48,40,32,24,16,8, 
57,49,41,33,25,17,9,1, 
59,51,43,35,27,19,11,3, 
61,53,45,37,29,21,13,5, 
63,55,47,39,31,23,15,7 
}; 

vector<int> innerInvPerm = { // Inverse permutation table for reversing the permutation step of the fiestal round (4th step)
9,17,23,31,13,28,2,18,
24,16,30,6,26,20,10,1,
8,14,25,3,4,29,11,19,
32,12,22,7,5,27,15,21
};

vector<int> innerPerm = { // Permutation table for the permutation step of the fiestal round (4th step)
16,7,20,21,29,12,28,17, 
1,15,23,26,5,18,31,10, 
2,8,24,14,32,27,3,9,
19,13,30,6,22,11,4,25 
}; 

vector<int> expansionRight = { // Expansion table for expanding 32-bit right segment into 38-bits in each round
32,1,2,3,4,5,4,5, 
6,7,8,9,8,9,10,11, 
12,13,12,13,14,15,16,17, 
16,17,18,19,20,21,20,21, 
22,23,24,25,24,25,26,27, 
28,29,28,29,30,31,32,1 
}; 

string errBits; // The string that maps to a particular location in an S-box

string compCheck(48,'x'); // Utility string to compare found key bits with the last round key

string getRandHex(){ // Function to generate a 16-length hexadecimal string (64 bit in binary)
    static std::mt19937 gen(997); //Fixed random seet to ensure reproduceability
    static std::uniform_int_distribution<> distrib(0, 15);	
    string res;
    for(int i=0;i<16;i++){
    	char c;
    	int rv=distrib(gen);
    	c=rv<=9?'0'+rv:'a'+(rv-10);
    	res+=c;
    }
    return res;
}

string permute(string s, vector<int> shuffleArr){ // Permutes a given input string using a given permutation table
  	string perm; 
	for(int i = 0; i < shuffleArr.size(); i++){ 
		perm += s[shuffleArr[i]-1]; 
	}
	return perm;
}

string numToBin(int x,int minLen){// Converts decimal to binary with fixed minimum length. '0's are used for padding
	string res;
	while(x){
		char c = '0' +(x%2);
		res+=c;
		x/=2;
	}
	while(res.size()<minLen) res+="0";

	reverse(res.begin(),res.end());
	return res;
}

string errorStringGen(int i,int j,int k){ // Given the sbox number and a particular row/index location, the function generates a string that maps to that location as described in DES
	string row = numToBin(j,2);
	string col = numToBin(k,4);
	string res=row[0]+col+row[1];
	return res;
}

bool go(string orig,string faulty){ // Test if ciphertexts from original and faulty DES can be used to perform attack. If possible, perform attack and report key bits found.

	//Convert final ciphertexts to respective round 16 outputs
	string origUP = permute(orig,initialPermutation);
	string faultyUP = permute(faulty,initialPermutation);

	// Split strings to obtain L and R segments of 16th round for both ciphertexts
	string origL = origUP.substr(0,32),origR=origUP.substr(32);
	string fL = faultyUP.substr(0,32),fR=faultyUP.substr(32);

	// if right segment of round 15 is not same for both, then faulty S-Box element was accesed previous to round 16. Hence we cannot use it for the attack.
	if(origR != fR) return false;

	// At this point, the faulty S-Box element was accessed only in the last round

	// Inverse permute the left segments to reverse the last permutation step of the feistel round
	string oRaw = permute(origL,innerInvPerm);
	string fRaw = permute(fL,innerInvPerm);


	int indexLoc;
	for(int i=0;i<32;i+=4){ // Finds faulty S-Box by comparing outputs
		string oBG = oRaw.substr(i,4);
		string fBG = fRaw.substr(i,4);
		if(oBG == fBG) continue; // If faulty S-Box element is accessed, the outputs for original and faulty DES will not be the same.
		indexLoc=i; // Record inital bit which differs from original.
		break; 

	}

	string expandedR;
	for(int i = 0; i < 48; i++) { // expand R15 to 48 bits since S-Box input takes a 48-bit segment divided into 6-bit lenghts
  		expandedR += origR[expansionRight[i]-1]; 
	};  

	string keyBits;
	int blockNum = indexLoc/4; // Cacluate faulty S-Box number (0 indexed)
	int keyStart = blockNum*6; // bits of expanded R15 which are input to the faulty S-Box

	for(int i=keyStart;i<keyStart+6;i++){ 
		keyBits+=errBits[i-keyStart] == expandedR[i]?"0":"1"; //Key is calculates by taking the xor of Error with faulty S-Box input
		compCheck[i]=keyBits[i-keyStart];
	}	
	return true;
}

void tester(int sboxNum){ //Function to perform PF attack on a particular S-BOX. Reports key bits found aswell as average number of ciphertexts needed to obtain the key bits.
	string key=getRandHex();// Sets a random hexadecimal string as key

	cout<<"TRIAL FOR SBOX #"<<sboxNum<<endl;
	cout<<"Randomly generated key (in Hex):"<<endl<<key<<endl;

    DES a(key); // Original DES with no faulty S-Box
    DES faulty(key);// DES with faulty S-Box

    int j=rand()%4, k=rand()%16; // Randomise S-Box fault location/index

    //Randomise substituted error value and make sure error value != original value
    int newVal = faulty.sBox[sboxNum][j][k];
    newVal = (newVal + (rand()%63) + 1)%64;

    cout<<"FAULT IN SBOX - "<<sboxNum<<": Replaced S-Box element at index ["<<j<<"]["<<k<<"] with new value = "<<newVal<<endl;

    faulty.setFault(newVal,sboxNum,j,k); // Inject fault into the designated faulty S-Box
    errBits = errorStringGen(sboxNum,j,k); //Generate string that maps to error location in the faulty S-Box

	string text;
	long int sum=0; // Sum of ciphertexts needed to perform attack over all iterations 
	const int ITER_LIM=50; // Number of attack trials

	for(int ITER=0;ITER<ITER_LIM;ITER++){ // Loop over attack trials

	for(int i=0;;i++){ // Generate random plaintexts until attack can be performed 
		string text=getRandHex(); // Random plaintext generation

		auto x1=a.calc(text); // Compute ciphertext using normal DES
		auto x2=faulty.calc(text); // Compute ciphertext using faulty DES

		if(a._ct!=faulty._ct){ // If ciphertexts generated by normal and faulty DES are not same, faulty S-BOX was used in ciphertext generation.
			if(!go(a._ct,faulty._ct)){ // Check if attack cannot be perfomed and if it is possbile, perform it

				continue; // Ignores current plaintext and ciphertext
			}
			else{
				sum+=i+1; // Attack can be performed! Records plaintexts/ciphertexts generated and exits loop 
				break;
			}
		}
	}


	}

	//compares found key bits with original last round subkey
	cout<<"ORIGINAL LAST ROUND KEY vs FOUND BITS"<<endl<<a._subKeys[15]<<endl<<compCheck<<endl;

	double avg_iter = (double)sum/(double)ITER_LIM; //Average ciphertexts needed for attack

	cout<<"Average number of iterations over "<<ITER_LIM<<" trials :"<<avg_iter<<endl;	
	compCheck=string(48,'x');
	cout<<endl<<"------------------------------------------"<<endl;
}

int main(){ 
	for(int i=0;i<8;i++) tester(i); // Perform attack separately for each S-Box
} 