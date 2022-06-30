from cProfile import label
from django import forms


class SearchForm(forms.Form):
    searchResult = forms.CharField(widget=forms.TextInput(attrs={'class': 'searchInput'}), label="")