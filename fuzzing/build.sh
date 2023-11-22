cd "$SRC"/jc
pip3 install .

# Build fuzzers in $OUT
for fuzzer in $(find fuzzing -name '*_fuzzer.py');do
  compile_python_fuzzer "$fuzzer"
done
rm -rf fuzzing/corpus

# Populate a fuzzing corpus using all existing test fixtures
mkdir -p fuzzing/corpus
find tests/fixtures/ -type f -name "*.out" -exec cp {} fuzzing/corpus \;
zip -q $OUT/jc_fuzzer_seed_corpus.zip fuzzing/corpus/*
