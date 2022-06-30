from django.urls import reverse
from urllib.parse import urlencode
from django.shortcuts import render
from django.http import HttpResponse, HttpResponsePermanentRedirect
from django.shortcuts import redirect
from django.views.decorators.http import require_http_methods
from .forms import SearchForm
from django.template.loader import render_to_string
import requests
import nvdlib
import datetime
import pdfkit

API_KEY = '758aafd2-8220-4227-9db4-adc9faa548b6'

def index(request):
    return HttpResponsePermanentRedirect("/info")

def info(request):
    return render(request, "info.html")

@require_http_methods(["GET"])
def all(request):
    params = {"apiKey": API_KEY, }
    response = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=500", params)
    responseDict = response.json()
    responseDict["result"]["title"] = "All CVE"
    responseDict["result"]["url"] = "downloadAll"
    responseDict["result"]["urlParam"] = "downloadAll"
    return render(request, "getcve.html", context = responseDict["result"])

@require_http_methods(["GET"])
def new(request):  
    end = datetime.datetime.now()
    start = end - datetime.timedelta(days=7)
    response = nvdlib.searchCVE(pubStartDate=start, pubEndDate=end, limit = 500, key=API_KEY)
    result = {"CVE_Items": response, 'title': "New CVE", "url": "downloadAll", "urlParam": "downloadNew",}
    return render(request, "getcve.html", context = result)

@require_http_methods(["GET"])
def critical(request):  
    response = nvdlib.searchCVE(cvssV3Severity = 'Critical', limit = 500, key=API_KEY)
    result = {"CVE_Items": response, 'title': "Critical CVE", "url": "downloadAll", "urlParam": "downloadCritical"}
    return render(request, "getcve.html", context = result)
    
def byId(request):  
    if request.method == "POST":
        cveID = request.POST.get("searchResult")
        base_url = reverse('getSearchResult')
        query_string =  urlencode({'cveid': cveID}) 
        url = '{}?{}'.format(base_url, query_string)
        return redirect(url)
    else:
        searchForm = SearchForm()
        searchForm.fields["searchResult"].widget.attrs.update({'placeholder': 'Enter CVE ID'})
        return render(request, "search.html", {"form": searchForm})


def byKeyword(request):  
    if request.method == "POST":
        keyword = request.POST.get("searchResult")
        base_url = reverse('getSearchResult')
        query_string =  urlencode({'keyword': keyword}) 
        url = '{}?{}'.format(base_url, query_string)
        return redirect(url)
    else:
        searchForm = SearchForm()
        searchForm.fields["searchResult"].widget.attrs.update({'placeholder': 'Enter keyword'})
        return render(request, "search.html", {"form": searchForm})


def byProduct(request):  #oracle agile_plm 9.3.3, microsoft access 2002, apple apple_music 1.2.1
    if request.method == "POST":
        product = request.POST.get("searchResult")
        base_url = reverse('getSearchResult')
        query_string =  urlencode({'product': product}) 
        url = '{}?{}'.format(base_url, query_string)
        return redirect(url)
    else:
        searchForm = SearchForm()
        searchForm.fields["searchResult"].widget.attrs.update({'placeholder': 'Format: Vendor ProductFullName'})
        return render(request, "search.html", {"form": searchForm})

def getSearchResult(request):
    if 'cveid' in request.GET:
        try:
            response = nvdlib.getCVE(request.GET.get("cveid", ""), key=API_KEY)
        except:
            response = []
        finally:
            return render(request, "searchResult.html", context={"cve": response, "url": "downloadSearch", "urlParam": "cveid"})
    elif 'keyword' in request.GET:
        response = nvdlib.searchCVE(keyword = request.GET.get("keyword", ""), limit = 500, key=API_KEY)
        result = {"CVE_Items": response, 'title': "", "search": "true", "url": "downloadSearch", "urlParam": "keyword", "keyword": request.GET.get("keyword", "")}
        return render(request, "getcve.html", context = result)
    elif 'product' in request.GET:
        product = request.GET.get("product", "").replace(" ", ":")
        r = nvdlib.searchCPE(cpeMatchString='cpe:/:'+product, cves=True, key=API_KEY)
        result = []
        for eachCPE in r:
            for eachVuln in eachCPE.vulnerabilities:
                result.append(eachVuln)
        return render(request, "productcve.html", context = {'cves': result, "url": "downloadSearch", "urlParam": "product", "product": product})

@require_http_methods(["GET"])
def downloadAll(request, content=""):
    if content=="all":
        params = {"apiKey": API_KEY, }
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=7", params)
        responseDict = response.json()
        responseDict["result"]["title"] = "All CVEs"
        html = render_to_string("downloadContentTemplate.html", context = responseDict["result"])
    elif content=="new":
        end = datetime.datetime.now()
        start = end - datetime.timedelta(days=7)
        response = nvdlib.searchCVE(pubStartDate=start, pubEndDate=end, limit = 7, key=API_KEY)
        result = {"CVE_Items": response, 'title': "New CVEs"}
        html = render_to_string("downloadContentTemplate.html", context = result)
    elif content=="critical":
        response = nvdlib.searchCVE(cvssV3Severity = 'Critical', limit = 7, key=API_KEY)
        result = {"CVE_Items": response, 'title': "Critical CVEs"}
        html = render_to_string("downloadContentTemplate.html", context = result)

    pdf = pdfkit.from_string(html)
    response = HttpResponse(pdf,content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="cves.pdf"'
        
    return response
    

@require_http_methods(["GET"])
def downloadSearch(request):
    if 'cveid' in request.GET:
        response = nvdlib.getCVE(request.GET.get("cveid", ""), key=API_KEY)
        CVE_Items = [response]
        html = render_to_string('downloadContentTemplate.html', context={"CVE_Items":  CVE_Items})
       
    elif 'keyword' in request.GET:
        response = nvdlib.searchCVE(keyword = request.GET.get("keyword", ""), limit = 7, key=API_KEY)
        html = render_to_string('downloadContentTemplate.html', context={"CVE_Items": response, 'title': f"All cves that have {request.GET.get('keyword', '')} in description or reference links"})
       
    elif 'product' in request.GET:
        product = request.GET.get("product", "")
       
        r = nvdlib.searchCPE(cpeMatchString='cpe:2.3:a:'+product, cves=True, key=API_KEY)
        product = request.GET.get("product", "").replace(":", " ")
        result = []
        for eachCPE in r:
            for eachVuln in eachCPE.vulnerabilities:
                result.append(eachVuln)
        html = render_to_string('downloadProduct.html', context={"cves": result, "title": f"All cves related to the {product}"})
        
    
    pdf = pdfkit.from_string(html)
    response = HttpResponse(pdf,content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="cves.pdf"'
        
    return response