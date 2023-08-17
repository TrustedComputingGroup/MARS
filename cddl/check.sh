# This shell script tests various CBOR command and response blobs captured
# from input to and output from the MARS dispatcher against mars.cddl.
# Requires: zcbor

# chk <command> <response>
function chk {
  echo -e "\nChecking $1"
  echo $1 | zcbor validate -c mars.cddl -i - --input-as cborhex -t mars_command 2> /dev/null
  [ $? -ne 0 ] && echo BAD

  echo "Checking $2"
  echo $2 | zcbor validate -c mars.cddl -i - --input-as cborhex -t mars_response 2> /dev/null
  [ $? -ne 0 ] && echo BAD
}

chk 8200f5 8100
chk 820103 82001820
chk 820104 820010
chk 820105 820010
chk 820108 82001881
chk 8102 8100
chk 82034d544347204d4152532064656d6f 820040
chk 8104 82005820cf5fb1917db493fdcd89e406fd47195cf51c82079dee5681edd172cea2db819a
chk 8305005820cf5fb1917db493fdcd89e406fd47195cf51c82079dee5681edd172cea2db819a 8100
chk 820600 82005820633edbbf32fddb1133ccf024c28e23a437d055d38dae8314897be55c8c993a74
chk 830701505365616c656453746f726167654b6579 82005820f16545d50164ad2cd4d4434f9e786a61396bd9b49666c92414cb0a78c8a5bc20
chk 830801456368696c64 8100
chk 8309f543414b31 8105
chk 840a01582048984ce5d39b6e271e91bfaadaa15bafccfd32d8e192b9ea5dfc6f0aa399720143414b31 82005820630b4e485c3013ef57c27666383f8e2bab517e2dedb05c376d91cd3075635ce2
chk 850cf543414b315820883e3e6b7f7c00f9d23c4d0a3aa8d890db348f03b3fa5a06919d2ca2b6c609f85820630b4e485c3013ef57c27666383f8e2bab517e2dedb05c376d91cd3075635ce2 8200f5
chk 830b44756b65795820cf5fb1917db493fdcd89e406fd47195cf51c82079dee5681edd172cea2db819a 82005820c468a5b161bda186b08d4987dbb87e1cefeab76165402ee49f46e41480803f1a
