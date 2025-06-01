# core/forms.py

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
#from crispy_forms.helper import FormHelper
#from crispy_forms.layout import Layout, Submit, Row, Column, Field, HTML
from .models import UserProfile, DatabaseInfo

class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username',
            'autofocus': True
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('username', css_class='mb-3'),
            Field('password', css_class='mb-3'),
            Submit('submit', 'Login', css_class='btn btn-primary w-100')
        )

class UserProfileForm(forms.ModelForm):
    first_name = forms.CharField(max_length=30, required=False)
    last_name = forms.CharField(max_length=30, required=False)
    email = forms.EmailField(required=False)

    class Meta:
        model = UserProfile
        fields = ['wallet_address']
        widgets = {
            'wallet_address': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter wallet address (optional)'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.user:
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name
            self.fields['email'].initial = self.instance.user.email

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Row(
                Column('first_name', css_class='form-group col-md-6 mb-3'),
                Column('last_name', css_class='form-group col-md-6 mb-3'),
            ),
            Field('email', css_class='mb-3'),
            Field('wallet_address', css_class='mb-3'),
            Submit('submit', 'Update Profile', css_class='btn btn-primary')
        )

    def save(self, commit=True):
        profile = super().save(commit=False)
        if commit:
            # Update User model fields
            user = profile.user
            user.first_name = self.cleaned_data['first_name']
            user.last_name = self.cleaned_data['last_name']
            user.email = self.cleaned_data['email']
            user.save()
            profile.save()
        return profile

class SystemSettingsForm(forms.Form):
    session_timeout = forms.IntegerField(
        min_value=300,
        max_value=86400,
        help_text="Session timeout in seconds (5 minutes to 24 hours)"
    )
    max_login_attempts = forms.IntegerField(
        min_value=3,
        max_value=10,
        help_text="Maximum failed login attempts before account lockout"
    )
    enable_file_scanning = forms.BooleanField(
        required=False,
        help_text="Enable automatic file scanning for security threats"
    )
    max_upload_size = forms.IntegerField(
        min_value=1,
        max_value=1024,
        help_text="Maximum file upload size in MB"
    )
    backup_retention_days = forms.IntegerField(
        min_value=7,
        max_value=365,
        help_text="Number of days to retain database backups"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            HTML('<h5>Security Settings</h5>'),
            Row(
                Column('session_timeout', css_class='form-group col-md-6 mb-3'),
                Column('max_login_attempts', css_class='form-group col-md-6 mb-3'),
            ),
            Field('enable_file_scanning', css_class='mb-3'),
            HTML('<h5>File Management</h5>'),
            Field('max_upload_size', css_class='mb-3'),
            Field('backup_retention_days', css_class='mb-3'),
            Submit('submit', 'Save Settings', css_class='btn btn-primary')
        )

# databases/forms.py

from django import forms
from django.contrib.auth.models import User
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, Row, Column, Field, HTML
from core.models import DatabaseInfo
from .models import DatabaseUser

class DatabaseCreateForm(forms.ModelForm):
    SCHEMA_CHOICES = [
        ('empty', 'Empty Database'),
        ('document_management', 'Document Management'),
        ('user_management', 'User Management'),
        ('asset_management', 'Asset Management'),
        ('custom', 'Custom Schema'),
    ]

    schema_type = forms.ChoiceField(
        choices=SCHEMA_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta:
        model = DatabaseInfo
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter database name',
                'pattern': '[a-zA-Z0-9_]+',
                'title': 'Only letters, numbers, and underscores allowed'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Describe the purpose of this database'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('name', css_class='mb-3'),
            Field('description', css_class='mb-3'),
            Field('schema_type', css_class='mb-3'),
            HTML('<div id="schema-preview" class="alert alert-info" style="display: none;"></div>'),
            Submit('submit', 'Create Database', css_class='btn btn-primary')
        )

    def clean_name(self):
        name = self.cleaned_data['name']
        if DatabaseInfo.objects.filter(name=name).exists():
            raise forms.ValidationError('A database with this name already exists.')
        return name

class DatabaseEditForm(forms.ModelForm):
    class Meta:
        model = DatabaseInfo
        fields = ['description', 'is_active']
        widgets = {
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('description', css_class='mb-3'),
            Field('is_active', css_class='mb-3'),
            Submit('submit', 'Update Database', css_class='btn btn-primary')
        )

class DatabaseUserForm(forms.ModelForm):
    ROLE_CHOICES = [
        ('readonly', 'Read Only'),
        ('user', 'Standard User'),
        ('admin', 'Administrator'),
    ]

    user = forms.ModelChoiceField(
        queryset=User.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta:
        model = DatabaseUser
        fields = ['user', 'role']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('user', css_class='mb-3'),
            Field('role', css_class='mb-3'),
            HTML('<div class="alert alert-info"><strong>Role Permissions:</strong><ul id="role-permissions"></ul></div>'),
            Submit('submit', 'Add User', css_class='btn btn-primary')
        )

    def save(self, commit=True):
        instance = super().save(commit=False)
        
        # Set permissions based on role
        role_permissions = {
            'readonly': ['read'],
            'user': ['read', 'write'],
            'admin': ['read', 'write', 'admin', 'manage_users'],
        }
        
        instance.permissions = role_permissions.get(instance.role, ['read'])
        
        if commit:
            instance.save()
        return instance

class DatabaseSchemaForm(forms.Form):
    table_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter table name'
        })
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('table_name', css_class='mb-3'),
            HTML('<div id="fields-container"></div>'),
            HTML('<button type="button" class="btn btn-outline-secondary mb-3" onclick="addField()">Add Field</button>'),
            Submit('submit', 'Save Schema', css_class='btn btn-primary')
        )

# files/forms.py

from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, Field, HTML
from core.models import DatabaseInfo, FileUpload

class FileUploadForm(forms.Form):
    files = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            #'multiple': True,
            'accept': '.txt,.pdf,.doc,.docx,.xls,.xlsx,.csv,.json,.xml,.jpg,.jpeg,.png,.gif,.zip,.tar,.gz'
        })
    )
    database = forms.ModelChoiceField(
        queryset=DatabaseInfo.objects.none(),
        required=False,
        empty_label="No specific database",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Optional description for the uploaded files'
        })
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Filter databases based on user permissions
        if user.userprofile.role == 'admin':
            self.fields['database'].queryset = DatabaseInfo.objects.filter(is_active=True)
        else:
            self.fields['database'].queryset = DatabaseInfo.objects.filter(
                models.Q(owner=user) | models.Q(databaseuser__user=user),
                is_active=True
            ).distinct()

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('files', css_class='mb-3'),
            Field('database', css_class='mb-3'),
            Field('description', css_class='mb-3'),
            HTML('<div class="alert alert-info"><i class="fas fa-info-circle"></i> Files will be automatically scanned for security threats.</div>'),
            Submit('submit', 'Upload Files', css_class='btn btn-primary')
        )

class FileSearchForm(forms.Form):
    search_query = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search files by name...'
        })
    )
    database = forms.ModelChoiceField(
        queryset=DatabaseInfo.objects.all(),
        required=False,
        empty_label="All databases",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    file_type = forms.ChoiceField(
        choices=[
            ('', 'All types'),
            ('document', 'Documents'),
            ('image', 'Images'),
            ('archive', 'Archives'),
            ('data', 'Data files'),
        ],
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    status = forms.ChoiceField(
        choices=[
            ('', 'All statuses'),
            ('approved', 'Approved'),
            ('pending', 'Pending'),
            ('quarantined', 'Quarantined'),
            ('rejected', 'Rejected'),
        ],
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Filter databases based on user permissions
        if user.userprofile.role == 'admin':
            self.fields['database'].queryset = DatabaseInfo.objects.all()
        else:
            self.fields['database'].queryset = DatabaseInfo.objects.filter(
                models.Q(owner=user) | models.Q(databaseuser__user=user)
            ).distinct()

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Row(
                Column('search_query', css_class='form-group col-md-6 mb-3'),
                Column('database', css_class='form-group col-md-6 mb-3'),
            ),
            Row(
                Column('file_type', css_class='form-group col-md-4 mb-3'),
                Column('status', css_class='form-group col-md-4 mb-3'),
                Column(HTML('<label class="form-label">&nbsp;</label><br>'), css_class='col-md-4 mb-3'),
            ),
            Row(
                Column('date_from', css_class='form-group col-md-6 mb-3'),
                Column('date_to', css_class='form-group col-md-6 mb-3'),
            ),
            Submit('submit', 'Search', css_class='btn btn-primary me-2'),
            HTML('<a href="?" class="btn btn-outline-secondary">Clear</a>')
        )

# transactions/forms.py

from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, Row, Column, Field, HTML

class TransactionCreateForm(forms.Form):
    from_address = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter sender address'
        })
    )
    to_address = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter recipient address'
        })
    )
    amount = forms.DecimalField(
        max_digits=20,
        decimal_places=8,
        min_value=0.00000001,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': '0.00000000',
            'step': '0.00000001'
        })
    )
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Optional transaction description'
        })
    )
    priority = forms.ChoiceField(
        choices=[
            ('low', 'Low (Slower confirmation)'),
            ('normal', 'Normal'),
            ('high', 'High (Faster confirmation)'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Row(
                Column('from_address', css_class='form-group col-md-6 mb-3'),
                Column('to_address', css_class='form-group col-md-6 mb-3'),
            ),
            Row(
                Column('amount', css_class='form-group col-md-8 mb-3'),
                Column('priority', css_class='form-group col-md-4 mb-3'),
            ),
            Field('description', css_class='mb-3'),
            HTML('<div class="alert alert-warning"><i class="fas fa-exclamation-triangle"></i> Please verify all transaction details before submitting. Transactions cannot be reversed.</div>'),
            Submit('submit', 'Create Transaction', css_class='btn btn-primary')
        )

class MiningConfigForm(forms.Form):
    miner_address = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter miner address'
        })
    )
    mining_mode = forms.ChoiceField(
        choices=[
            ('single', 'Single Block'),
            ('continuous', 'Continuous Mining'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    cpu_threads = forms.IntegerField(
        min_value=1,
        max_value=16,
        initial=2,
        widget=forms.NumberInput(attrs={
            'class': 'form-control'
        })
    )
    auto_stop = forms.BooleanField(
        required=False,
        help_text="Automatically stop mining after specified time"
    )
    stop_after_minutes = forms.IntegerField(
        required=False,
        min_value=1,
        max_value=1440,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Minutes'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('miner_address', css_class='mb-3'),
            Row(
                Column('mining_mode', css_class='form-group col-md-6 mb-3'),
                Column('cpu_threads', css_class='form-group col-md-6 mb-3'),
            ),
            Field('auto_stop', css_class='mb-3'),
            Field('stop_after_minutes', css_class='mb-3'),
            HTML('<div class="alert alert-info"><i class="fas fa-info-circle"></i> Mining will consume CPU resources. Monitor system performance.</div>'),
            Submit('submit', 'Start Mining', css_class='btn btn-warning')
        )
