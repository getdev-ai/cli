# must NOT fire: AWS near-misses — wrong case, wrong length, wrong prefix
aws_key_lowercase = "AKIAfakefakefakefake"
aws_key_too_short = "AKIAFAKEFAKEFAKEFAK"
aws_key_wrong_prefix = "AXIAFAKEFAKEFAKEA1B2"
