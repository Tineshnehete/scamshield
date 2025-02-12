import csv
from django.core.management.base import BaseCommand
from scanner.models import DomainRank

class Command(BaseCommand):
    help = 'Import data from a CSV file into the DomainRank model'

    def handle(self, *args, **kwargs):
        # Replace with your actual CSV file path
        csv_file_path = 'l.csv'

        try:
            with open(csv_file_path, mode='r') as file:
                csv_reader = csv.DictReader(file)
                
                for row in csv_reader:
                    DomainRank.objects.create(
                        domain_name=row['domain'],
                        rank=int(row['rank'])  # Ensure the rank is an integer
                    )
            self.stdout.write(self.style.SUCCESS('Data imported successfully'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error occurred: {e}'))
