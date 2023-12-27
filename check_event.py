import json

import time

import requests

base_url = "http://127.0.0.1:5000/v1/crawler/zeroindexer/{}"


class atom:
    def __init__(self, mint_amount, ticker):
        self.mint_amount = mint_amount
        self.ticker = ticker
        self.current_mint_cnt = 0


class Balances:
    def __init__(self):
        self.balances = {}

    def add_balance(self, addr, ticket, value):
        if addr not in self.balances:
            self.balances[addr] = {}
        if ticket not in self.balances[addr]:
            self.balances[addr][ticket] = 0

        self.balances[addr][ticket] += value

    def print_details(self):
        for addr, tickets in self.balances.items():
            for ticket, value in tickets.items():
                print(f"Address: {addr}, Ticket: {ticket}, Value: {value}")


class MyStruct:
    def __init__(self):
        self.map = {}

    def handle_deploy(self, atom_data):
        self.map[atom_data.ticker] = atom_data

    def handle_mint(self, ticker):
        self.map[ticker].current_mint_cnt = self.map[ticker].current_mint_cnt + 1

    def print_detail(self):
        for ticket, info in self.map.items():
            print(f'ticker {ticket} info {info.mint_amount} {info.ticker} {info.current_mint_cnt}')


my_instance = MyStruct()
balance_instance = Balances()


def handle_context_tx_data(data):

    if len(data) == 7:
        print("----- deploy ----")
        atom_data = atom(data["args"]["mint_amount"], data["args"]["request_ticker"])
        my_instance.handle_deploy(atom_data)
    elif len(data) == 6:
        print("---- mint -----")
        balance_instance.add_balance(data["address"], data["mint_ticker"],
                                     my_instance.map[data["mint_ticker"]].mint_amount)
        my_instance.handle_mint(data["mint_ticker"])

    else:
        print("others")


def main():
    for i in range(0, 600):
        url = base_url.format(i)
        response = requests.get(url)

        if response.status_code == 200:
            response_data = json.loads(response.text)
            if response_data["code"] == 0:
                data = json.loads(response.text)["data"]
                dataMap = json.loads(data)
                txs = dataMap["txs"]
                if len(txs) != 0:
                    for tx in txs:
                        context_data = tx["inscription_context"]
                        handle_context_tx_data(context_data)
        else:
            print(f"请求失败，状态码: {response.status_code}")

    balance_instance.print_details()
    my_instance.print_detail()


if __name__ == '__main__':
    main()
