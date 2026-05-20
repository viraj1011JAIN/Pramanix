from pramanix import Policy

policy = Policy().deny(lambda intent, state: intent['amount'] > 100).explain('You cannot perform this trade because it exceeds your daily risk limit.')
