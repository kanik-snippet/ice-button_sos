from django.shortcuts import get_object_or_404, render
from .models import BlogPost,FollowUs,BlogComment
# Create your views here.
from django.db.models import Q
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from rest_framework.decorators import api_view
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from googletrans import Translator
from drf_yasg import openapi
from rest_framework.permissions import AllowAny


# def blog(request):
#     return render(request, "blogs/blog.html")


class BlogGridApiView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this API

    """
    Get a list of blog posts with optional category filtering and search functionality.
    """

    @swagger_auto_schema(
        operation_description="Fetch a list of blog posts with optional filtering by category and search functionality",
        responses={200: BlogPostSerializer(many=True)},  # Expected response structure
        manual_parameters=[
            openapi.Parameter('category', openapi.IN_QUERY, description="Filter blogs by category", type=openapi.TYPE_STRING),
            openapi.Parameter('search', openapi.IN_QUERY, description="Search blogs by title", type=openapi.TYPE_STRING),
        ]
    )
    def get(self, request, category=None):
        """
        Get a list of blog posts with optional category filtering and search functionality.
        """
        blogs = BlogPost.objects.all()

        # Filter by category if provided
        if category:
            blogs = blogs.filter(category=category)

        # Search functionality
        search_query = request.GET.get('search', None)
        if search_query:
            blogs = blogs.filter(title__icontains=search_query)

        # Serialize the blog data
        serializer = BlogPostSerializer(blogs, many=True)

        # Return the serialized data in the response
        return Response(serializer.data, status=status.HTTP_200_OK)


# Blog Details API View
class BlogDetailsApiView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this API

    """
    Get a specific blog post by its slug.
    """

    @swagger_auto_schema(
        operation_description="Fetch a single blog post by slug",
        responses={200: BlogPostSerializer, 404: 'Not Found'},  # Expected response structure
        manual_parameters=[
            openapi.Parameter('slug', openapi.IN_PATH, description="Slug of the blog post", type=openapi.TYPE_STRING),
        ]
    )
    def get(self, request, slug):
        """
        Get a specific blog post by its slug.
        """
        try:
            # Retrieve the blog post by slug
            blog = BlogPost.objects.get(slug=slug)
        except BlogPost.DoesNotExist:
            # Return a 404 response if the blog post does not exist
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the blog data
        serializer = BlogPostSerializer(blog)

        # Return the serialized data in the response
        return Response(serializer.data, status=status.HTTP_200_OK)

class FollowUsAPI(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this API

    def get(self, request, *args, **kwargs):
        follow_us = FollowUs.objects.first()
        serializer = FollowUsSerializer(follow_us)
        return Response(serializer.data)


from django.shortcuts import render
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from googletrans import Translator
from .models import BlogPost
from django.utils.translation import get_language

# Initialize Translator
translator = Translator()

# Function to translate text
def translate_text(text, target_language='hi'):
    from googletrans import Translator
    translator = Translator()

    # Explicitly specify the source language as 'en' (English)
    translated = translator.translate(text, src='en', dest=target_language)
    
    print(f"Translating text: {text} to {target_language}")
    print(f"Translated text: {translated.text}")
    
    return translated.text



def blogGrid(request, category=None, page=1):
    print("Starting blogGrid view...")

    # Capture the search query from GET request
    search_query = request.GET.get('search', None)
    print(f"Search query: {search_query}")

    # Filter blog posts based on search query or category
    if search_query:
        print(f"Filtering blog posts with search query: {search_query}")
        blog_posts = BlogPost.objects.filter(title__icontains=search_query)
    elif category:
        print(f"Filtering blog posts by category: {category}")
        blog_posts = BlogPost.objects.filter(category=category)
    else:
        print("No search query or category provided; fetching all blog posts.")
        blog_posts = BlogPost.objects.all()

    # Paginate blog posts (12 posts per page)
    paginator = Paginator(blog_posts, 12)
    print(f"Paginator created with 12 posts per page.")
    try:
        blog_posts = paginator.page(page)
        print(f"Fetched page {page} of blog posts.")
    except PageNotAnInteger:
        print("Page is not an integer; fetching the first page.")
        blog_posts = paginator.page(1)
    except EmptyPage:
        print("Page is empty; fetching the last page.")
        blog_posts = paginator.page(paginator.num_pages)

    # Get recent blog posts (e.g., the last 6)
    print("Fetching recent blog posts...")
    recent_posts = BlogPost.objects.all().order_by('-created_at')[:6]
    print(f"Fetched {len(recent_posts)} recent posts.")

    # Handling the translation language based on the django_language cookie
    language = request.COOKIES.get('django_language', 'en')
    print(f"Selected language from cookie: {language}")

    # Translate blog titles, categories, and "created by" names if the selected language is not English
    if language == 'hi':  # If the target language is Hindi
        print(f"Translating blog details to {language}...")
        for blog in blog_posts:
            blog.title = translate_text(blog.title, target_language='hi')
            blog.category = translate_text(blog.category, target_language='hi')
            blog.translated_created_by = translate_text(str(blog.created_by.name), target_language='hi')  # Temporary field
        for post in recent_posts:
            post.title = translate_text(post.title, target_language='hi')
            post.category = translate_text(post.category, target_language='hi')
            post.translated_created_by = translate_text(str(post.created_by.name), target_language='hi')  # Temporary field

    print("Rendering the blogGrid template...")
    return render(request, "blogs/blogGrid.html", {
        'title': translate_text('Blog Grid (ICE Button SOS)', target_language=language) if language != 'en' else 'Blog Grid (ICE Button SOS)',
        'blog_posts': blog_posts,
        'search_query': search_query,
        'recent_posts': recent_posts,
        'language': language,  # Pass the selected language to the template
    })

def blogDetails(request, slug, category=None):
    # Fetch the individual post using the slug
    post = get_object_or_404(BlogPost, slug=slug)

    # Fetch the recent 5 posts, ordered by created_at (latest first)
    recent_posts = BlogPost.objects.all().order_by('-created_at')[:6]

    # Get the language from the request
    language = request.COOKIES.get('django_language', 'en')
    print(f"Selected language: {language}")  # Debugging statement

    # Translate content if language is Hindi ('hi')
    if language == 'hi':
        print("Translating to Hindi...")

        # Translate title, description, and content only if they are not None
        if post.title:
            print(f"Original title: {post.title}")
            post.title = translate_text(post.title, target_language='hi')
        else:
            print("No title to translate.")
        
        if post.description:
            print(f"Original description: {post.description}")
            post.description = translate_text(post.description, target_language='hi')
        else:
            print("No description to translate.")
        
        if post.content:
            print(f"Original content: {post.content[:50]}...")  # Show first 50 characters for debugging
            post.content = translate_text(post.content, target_language='hi')
        else:
            print("No content to translate.")

        if post.created_by and post.created_by.name:
            print(f"Original created_by name: {post.created_by.name}")
            post.created_by.name = translate_text(post.created_by.name, target_language='hi')
        else:
            print("No created_by name to translate.")

        # Translate the category
        if post.category:
            print(f"Original category: {post.category}")
            post.category = translate_text(post.category, target_language='hi')
        else:
            print("No category to translate.")

        # Translate recent posts if they are not None
        for recent_post in recent_posts:
            if recent_post.title:
                print(f"Original recent post title: {recent_post.title}")
                recent_post.title = translate_text(recent_post.title, target_language='hi')
            else:
                print("No recent post title to translate.")
            if recent_post.description:
                print(f"Original recent post description: {recent_post.description}")
                recent_post.description = translate_text(recent_post.description, target_language='hi')
            else:
                print("No recent post description to translate.")
            if recent_post.content:
                print(f"Original recent post content: {recent_post.content[:50]}...")  # Show first 50 characters for debugging
                recent_post.content = translate_text(recent_post.content, target_language='hi')
            else:
                print("No recent post content to translate.")
                
            if recent_post.created_by and recent_post.created_by.name:
                print(f"Original recent post created_by name: {recent_post.created_by.name}")
                recent_post.created_by.name = translate_text(recent_post.created_by.name, target_language='hi')
            else:
                print("No recent post created_by name to translate.")
            if recent_post.category:
                print(f"Original recent post category: {recent_post.category}")
                recent_post.category = translate_text(recent_post.category, target_language='hi')
            else:
                print("No recent post category to translate.")

    # Fetch FollowUs links
    follow_us = FollowUs.objects.first()

    # Fetch approved comments for the blog post
    approved_comments = BlogComment.objects.filter(blog=post, is_approved=True)

    return render(request, "blogs/blogDetails.html", {
        'post': post,
        'recent_posts': recent_posts,
        'search_results': None,
        'search_query': '',
        'blog_posts': BlogPost.objects.all(),
        'follow_us': follow_us,
        'approved_comments': approved_comments,
        'language': language  # Pass the selected language to the template
    })