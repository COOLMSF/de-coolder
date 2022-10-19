#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

using namespace std;

#define MAX_LEN 512

static int cnt = 0;
uint8_t shellcode[MAX_LEN] = { 0 };
std::string raw_string = R"(\1f\8b\08\00\00\00\00\00\04\00\ed\bd\07`\1cI\96%&/m\ca{\7fJ\f5J\d7\e0t\a1\08\80`\13$\d8\90@\10\ec\c1\88\cd\e6\92\ec\1diG#)\ab*\81\caeVe]f\16@\cc\ed\9d\bc\f7\de{\ef\bd\f7\de{\ef\bd\f7\ba;\9dN'\f7\df\ff?\\fd\01l\f6\ceJ\da\c9\9e!\80\aa\c8\1f?~|\1f?\"~\8d_\f3\d7\f85~\8d\ff\fb\ff\fe\bf\ffo\fc\c4\ff~\a3_\eb\d7\f85~\8dg?\95\ad\9e\d5\d9\"\bf\aa\ea\b7\a3\f4'\f3\ba)\aa\e5g{;\bb\9f\8ew\e8\bf\ddQz\b2.\dbu\9d\7f\b6\cc\d7m\9d\95\a3\f4\e5zR\16\d3\df+\bf~S\bd\cd\97\9f-\d7e\f9\1b\fd\da\bf\c6\af\f1k\bcx}\dd\b4\f9b\fc4k3\0f\14\c3\d9\b9\19\ce\e4\c1\83\ec\fe\f4\fe\a7\bb\0f\ef\ed\e7;\07\0f\7f] \fa\b1\8f\df\f8\a4Z,\aa\e5\f8\bb\f9\04}\fcd\91_\bd\cc\e8\cb6\af\7f\9b_\e3\d7\f85~\ecM6)\f3\17\d9\"\ff\8d\08\e8\b3\"/g\f8\e37y\fd\8bJ\bc\98-go\f2w\edo|\d6x\7f\fdF\06\d0\e7\ebb\f6\1b\bc\cc.\f2\d7\c5\0f\f2\1f\c3/g\cbY\fe\ee7zV\94m^\bfn\ebby\f1\1b\9e\ac\eb\a6\aa\01\b4\f91\86\8f\b7~\03\ea\ec'\b3r\9d\ffF\af\f3\f6yU\bd\a5W\f2\d9\8f\9dd\d3y\fe\ac\cc.~\c3\cf\f3\16\bd\e0\f7\df\f0U>\adjF\ab\f9\f5\de\14\d3\b7y\fb\9b\e0\bb\d7\d5\ba\9e\e6\80\96|\91\b7\f3j\f6)";
// std::string raw_string = R"(o\b8\a6\d7\84u\cc\87R\b8\0a\b5NHk\b8\a0__\b2 \8a\cbdA\947\86W\ad\95Yi\b5\03\dd\02f\95V\dd\a2\ac\d5\d1\b4\9a\d1.\c0\b6\d6.\e0\89\b5o\bc\bf{\ff\cb\dd\c7W\07\d7\1e\af\0e>\b9\bd{\f9\d7\c5\9do\f6\fer~\e6^Jc\9cc<\ec\ff\c7u\cdK\e3\acpt\e8\d01\d2\ca\85{7\7f.7\e8?\85\dd\a9J\\F\a6G\e9,E\87+\fa\f4V!\abE\f8J\d3\f7\d9p\0f!\d3^\8aDw\15A\bfK_\f3\d2\9a\9c\8bN( ]|6\d5\d1l\9a\0d\0a200\0d\0aQ@j[* %\17\07\9f\\\df\de\fa\15Q\f9\83\d1\ed\bb\9f?\de\b9\f75\e5\d3\c1\95\fb{o\bdG\b1\b4J\e9\ce\8d\8b\c5\dd\df\17\7f\b8H\d4n?\dc\dcy\f3\e6\de\d6\17\df\1b=P\0bs\a7t\08IMgd\daJg\aaeQZ\0aa9Sa\8f\ebV\f6\a2\b2|\ee\ba\06T\0f\8fK\f4\9f|\f4YW\13\99:u\c2+\cfM\e8\d7S;\ef7\96\86\df3\a3\9dIO\9d\b2\c4:}\c2\d5\fa\ca\d4\a9\e2\a1?A\93\adn\89/\e8w\a68\dfD\b3h\c6\05}\d7\d6\05\fdos2\bf:\86t\98T\c7\d3\01\83\cb\ffK\ff\7f\ef\bd\b7\8b\df\9d\df\de\fa}\f1\e0q\f1\f1\c3\d9\a7X\ca\1c\8er\ac\a3C\c8V\9dUL\f1P\ed\c2\87KUZh}\c5\e7}\8dj\\\c2\7f8\bfI`\0f\a0\8d\c5X\e6\e8\06i\d8\b0\be\e3\95\ea\aa\8e\b0\f6E\85\d9\a2\14\b4>1\c1Jor\b5\ca)\95\d3 \d0-\f1%\fe\ceDX\13\8d\b0\19\d7\f8])";

int main(int argc, char const* argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s outfile", argv[0]);
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < raw_string.length(); i++) {
  	  // if current char is '\', select the following 2 chars
  	  // else if current char is an ascii, select the num of ascii
  	  if (raw_string[i] == '\\') {
  	    std::string tmp_str = "";
  	    int tmp_int;

  	    // \0a\\F, in this situation, contiguous '\', will not care
  	    if (raw_string[i+1] == '\\') {
  	      // get the following 2 chars, from current char
  	      for (int j = 0; j < 2; j++) {
  	        tmp_str += raw_string[i+j];
  	        // std::cout << "current char is :" << raw_string[i+j];
  	      }
  	    } else {
  	      // get following 2 chars, from the next char
  	      for (int j = 1; j <= 2; j++) {
  	        tmp_str += raw_string[i+j];
  	        // std::cout << "current char is :" << raw_string[i+j];
  	      }
  	    }
  	    // update index
  	    i += 2;

  	    sscanf(tmp_str.c_str(), "%x", &tmp_int);
  	    shellcode[cnt++] = tmp_int;
  	  } else {
  	    int tmp_int = raw_string[i];
  	    shellcode[cnt++] = tmp_int;
  	  }

  	}

  	// write to file
  	FILE *fout = fopen(argv[1], "wb");
  	if (!fout) {
  	  perror("fopen");
  	  exit(EXIT_FAILURE);
  	}
  	fwrite(shellcode, cnt, 1, fout);
  	fclose(fout);

  	return 0;
}
